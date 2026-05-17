# Ghidra Decompiler IPC Protocol

> Spec for replacing Ghidra's Java `DecompileProcess` host with a Rust host while
> keeping the upstream C++ decompiler (`decompile` / `ghidra_process.cc`) binary.
> All citations point to `NationalSecurityAgency/ghidra@master` on GitHub so they
> can be independently verified.
>
> **Tracking:** beads issue `ghidra-cli-z26`. Companion: `docs/VISION.md` Phase 3.

---

## 1. Topology

```
                  stdout (decompiler -> host)
   +----------+   <===========================   +-------------+
   |  HOST    |                                  |   C++       |
   |  (today: |   stdin  (host -> decompiler)    |  decompiler |
   |   Java   |   ===========================>   | (decompile  |
   | Decompile|                                  |  executable)|
   | Process) |                                  +-------------+
   +----------+
```

The decompiler is a **child process** of the host. The host launches the
`decompile` executable (one process per registered program, see
`registerProgram` below) and communicates over its `stdin`/`stdout`.

The C++ `main` loop is in
`Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc:451-459`:

```cpp
while(status == 0) {
  status = GhidraCapability::readCommand(cin, cout);
}
```

This is a simple blocking single-threaded request/response server. There is
**no startup handshake** — the decompiler immediately calls `readCommand`
after initialising signal handlers and ID tables
(`ghidra_process.cc:446-450`).

Bidirectional traffic exists in two flavours:

1. **Top-level commands** (host -> decompiler): the host issues one of a small
   fixed set of commands (`registerProgram`, `decompileAt`, etc.) and reads a
   single top-level response.
2. **Callback queries** (decompiler -> host): *while servicing a top-level
   command*, the decompiler frequently asks the host for program facts
   (bytes, symbols, p-code, register info, ...). The host must answer each
   callback before the original top-level command's response will arrive.

Replacing the Java host means correctly serving both directions.

---

## 2. Wire framing

The wire is a **byte stream** with a small set of 4-byte "alignment burst"
markers. Each marker is `0x00 0x00 0x01 <type>`. The leading zero bytes
sentinel allows recovery from out-of-sync state (the C++ side's
`readToAnyBurst()` scans until it sees the pattern).

### 2.1 Frame markers

From `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileProcess.java:38-46`:

```java
private final static byte[] command_start        = { 0, 0, 1, 2 };
private final static byte[] command_end          = { 0, 0, 1, 3 };
private final static byte[] query_response_start = { 0, 0, 1, 8 };
private final static byte[] query_response_end   = { 0, 0, 1, 9 };
private final static byte[] string_start         = { 0, 0, 1, 14 };
private final static byte[] string_end           = { 0, 0, 1, 15 };
private final static byte[] exception_start      = { 0, 0, 1, 10 };
private final static byte[] exception_end        = { 0, 0, 1, 11 };
private final static byte[] byte_start           = { 0, 0, 1, 12 };
private final static byte[] byte_end             = { 0, 0, 1, 13 };
```

There are additional codes referenced on the C++ side
(`ghidra_arch.cc:70-85` and `:138-148`) that complete the table:

| Type | Hex  | Name (Java side)           | C++ semantics                                  |
|------|------|----------------------------|------------------------------------------------|
| 2    | 0x02 | `command_start`            | "Top-level command from host" open             |
| 3    | 0x03 | `command_end`              | "Top-level command from host" close            |
| 4    | 0x04 | (query_start)              | Callback query from decompiler open            |
| 5    | 0x05 | (query_end)                | Callback query from decompiler close           |
| 6    | 0x06 | (command_response_start)   | Response to top-level command open             |
| 7    | 0x07 | (command_response_end)     | Response to top-level command close            |
| 8    | 0x08 | `query_response_start`     | Response to callback open                      |
| 9    | 0x09 | `query_response_end`       | Response to callback close                     |
| 10   | 0x0a | `exception_start`          | Exception/error open                           |
| 11   | 0x0b | `exception_end`            | Exception/error close                          |
| 12   | 0x0c | `byte_start`               | Raw byte stream open                           |
| 13   | 0x0d | `byte_end`                 | Raw byte stream close                          |
| 14   | 0x0e | `string_start`             | String payload open                            |
| 15   | 0x0f | `string_end`               | String payload close                           |
| 16   | 0x10 | (warning_start)            | "Native message" warning open (cf. line 384)   |
| 17   | 0x11 | (warning_end)              | "Native message" warning close                 |

Notes:
- The 4-byte sentinel makes the stream **self-synchronising** but **not
  length-delimited** — there is no payload-length header. A frame extends
  until the matching close marker is encountered.
- Strings can be empty (just `string_start` immediately followed by
  `string_end`).
- The C++ side's `readToAnyBurst()` (`ghidra_arch.cc:70-85`) implements the
  scan: it consumes bytes until it sees `\000\000\001` and then returns the
  fourth byte as the type code.

### 2.2 Byte stream encoding (`byte_start`/`byte_end`)

`getBytes` and `getStringData` return **memory bytes** but cannot put raw
zero bytes inside a `byte_start`/`byte_end` frame (the sentinel would
collide). Java encodes each 8-bit byte as **two ASCII characters in the
range `A`-`P`**, where each character carries one nibble offset from `A`
(i.e. `A=0`, `B=1`, ..., `P=15`). See `DecompileProcess.java:879-896`
(`getBytes`) and the C++ decode in `ghidra_arch.cc:467-495`.

This is **not standard hex**. A Rust host must replicate the same
A-nibble encoding.

### 2.3 String stream payloads

Most non-trivial query *parameters* and *responses* are written as XML-ish
structured documents wrapped in a `string_start`/`string_end` frame. The
encoding inside is **PackedEncode** — Ghidra's compact binary encoding of
the same logical XML element tree exposed via the `Decoder` interface.
The C++ uses `PackedEncode` (`ghidra_arch.cc:132-136` `writeStringStream`)
and reads with `PackedDecode` (`ghidra_process.cc:206` `Address::decode`).

This means **the Rust host must implement PackedDecode/PackedEncode** to
participate. It is not free-form XML on the wire. (The format is the same
binary scheme used everywhere else in Ghidra's encoded-XML APIs; specs are
in `Ghidra/Features/Decompiler/src/decompile/cpp/marshal.{hh,cc}` upstream.)

### 2.4 Top-level command frame layout

From `DecompileProcess.java:532-538` (`registerProgram`):

```
command_start
  string_start "registerProgram" string_end
  string_start <pspec  xml>       string_end
  string_start <cspec  xml>       string_end
  string_start <tspec  xml>       string_end
  string_start <core   xml>       string_end
command_end
```

The general schema is: `command_start`, a name string, then zero or more
parameter strings, then `command_end`. Parameter count and types are
implicit in the command name. See `sendCommand`, `sendCommandTimeout`,
`sendCommand1Param`, `sendCommand2Params` at
`DecompileProcess.java:580-728` for the canonical writers.

### 2.5 Top-level command response

The C++ side wraps successful command responses in a single
`string_start`/`string_end` frame (see e.g. `RegisterProgram::rawCommand`
at `ghidra_process.cc:104-143` writing the arch ID, or
`DecompileAt::rawCommand` at `ghidra_process.cc:202-239` writing a
PackedEncode `ELEM_DOC` element). On the Java side these arrive at
`readResponse()` and are classified by the type byte read off the wire.

**Important asymmetry:** the C++ side does not appear to bracket the
top-level response in matching type-6/type-7 markers in normal operation;
it writes the result string directly inside type-14/15 (with type-16/17
or type-10/11 for warnings and exceptions intermixed). The Java reader
treats those higher-level brackets as the main signal — see the type
dispatcher at `DecompileProcess.java:436-499`.

> Verification gap: I have not exhaustively confirmed that the type-6/7
> brackets are unused in current upstream. A Rust host should be permissive
> and accept either bracketed-or-not framing on the response side.

### 2.6 Exception frame

`exception_start` (type 10) opens an exception. The C++ side reads two
strings inside: an exception type and a message, then `exception_end`
(`ghidra_arch.cc:138-148` `readToResponse`). Either side can emit these.
A Rust host should treat any callback returning an exception as a
recoverable "callback failed" signal and forward it appropriately.

---

## 3. Top-level commands (host -> decompiler)

Registered in `GhidraDecompCapability::initialize()`
(`ghidra_process.cc:437-444`):

| # | Command name           | C++ class             | Where |
|---|------------------------|------------------------|-------|
| 1 | `registerProgram`      | `RegisterProgram`      | `ghidra_process.cc:104-143` |
| 2 | `deregisterProgram`    | `DeregisterProgram`    | `ghidra_process.cc:145-180` |
| 3 | `flushNative`          | `FlushNative`          | `ghidra_process.cc:182-200` |
| 4 | `decompileAt`          | `DecompileAt`          | `ghidra_process.cc:202-239` |
| 5 | `structureGraph`       | `StructureGraph`       | `ghidra_process.cc:241-265` |
| 6 | `setAction`            | `SetAction`            | `ghidra_process.cc:267-310` |
| 7 | `setOptions`           | `SetOptions`           | `ghidra_process.cc:312-342` |

That's the entire surface area of the host->decompiler direction.

### 3.1 `registerProgram`

Java sender: `DecompileProcess.registerProgram()` at
`DecompileProcess.java:516-547`.

**Request payload (after the command name):** four strings, each a
PackedEncode XML document.

- `pspec` — processor spec (e.g. `x86-64.pspec`)
- `cspec` — compiler spec (e.g. `gcc-x86-64.cspec`)
- `tspec` — translator/SLEIGH spec (the architecture's sleigh `.sla`
  metadata; not the full .sla, but a reference plus options)
- `coretypes` — core data type description (built-in types like `int`,
  `void`, pointer width, etc.)

**Response:** a single `string_start`/`string_end` frame containing a
decimal architecture id as ASCII text (the Java side parses it with
`Integer.parseInt(response.toString())` at line 546). The id is then
used as the `archId` parameter on every subsequent top-level command.

**Why this matters for Rust:** the Rust host owns the `pspec`/`cspec`/
`tspec` content. For a first cut these can be lifted verbatim from
Ghidra's `Ghidra/Processors/x86/data/languages/` directory and shipped
as text-resource assets.

### 3.2 `deregisterProgram`

Sender: `DecompileProcess.deregisterProgram()` at
`DecompileProcess.java:552-575`.

**Request:** one parameter — the `archId` as a decimal string.

**Response:** a single string carrying a success flag (`"1"`/`"0"`).
Tears down the architecture in the decompiler.

### 3.3 `flushNative`

Sender: `DecompileProcess.flushCache()` (referenced but not shown — uses
`sendCommand`).

**Request:** the `archId` string.

**Response:** a single string carrying a result code. Tells the
decompiler to drop cached translations, symbol info, etc. and reread on
next callback.

### 3.4 `decompileAt`

Sender: `DecompileProcess.decompileAt()` (not shown — uses
`sendCommand1Param`).

**Request:** `archId` plus one parameter, a PackedEncode address element
(`ghidra_process.cc:202-239`, line 206:
`addr = Address::decode(decoder)`).

**Response:** a single PackedEncode `<doc>` element (`ELEM_DOC` in
`ghidra_process.cc:227-237`) containing the high-level decompiler output
(C-like source, transformed p-code, signature, warnings...).

This is **the** command we ultimately care about. Everything else exists
to support it.

### 3.5 `structureGraph`

Request: an encoded graph; response: an encoded transformed graph. Used
for control-flow structuring without performing a full decompile.

**Phase 3 priority: low.** Skip in MVP.

### 3.6 `setAction`

Request: two strings — action name (e.g. `"decompile"`, `"normalize"`)
and print mode (e.g. `"c-language"`, `"xml"`).
Response: `"t"` or `"f"`.

Required at least once to choose the decompile pipeline. The Java side
calls `setAction("decompile","")` (or similar) right after
`registerProgram` per the upstream code.

### 3.7 `setOptions`

Request: one PackedEncode options document.
Response: `"t"` or `"f"`.

Tunes timeout, max instructions, simplification flags, etc. Not strictly
required for correctness — the decompiler has defaults.

---

## 4. Callback queries (decompiler -> host)

This is the meat of the spec — the 19 callbacks the Rust host must
service. The dispatch table lives in `DecompileProcess.readResponse()`
at `DecompileProcess.java:450-510`. Each entry compares the inbound
command-name string and routes to a handler.

C++ senders all live in `ghidra_arch.cc` (`ArchitectureGhidra::...` methods).
Wire-name strings shown below are the **exact strings sent by the C++ side**
(quoted as in `ghidra_arch.cc`); the Java COMMAND_* constants match 1:1.

| # | Wire name                  | Java handler            | Java line | C++ sender                            | C++ line |
|---|----------------------------|-------------------------|-----------|---------------------------------------|----------|
| 1 | `command_isnameused`       | `isNameUsed`            | 920       | `isNameUsed`                          | 370-386  |
| 2 | `command_getbytes`         | `getBytes`              | 879       | `getBytes`                            | 467-495  |
| 3 | `command_getcomments`      | `getComments`           | 863       | `getComments`                         | 443-458  |
| 4 | `command_getcallfixup`     | `getPcodeInject`        | 732       | `getPcodeInject`                      | 560-596  |
| 5 | `command_getcallotherfixup`| `getPcodeInject`        | 732       | `getPcodeInject`                      | 560-596  |
| 6 | `command_getcallmech`      | `getPcodeInject`        | 732       | `getPcodeInject`                      | 560-596  |
| 7 | `command_getpcodeexecutable`| `getPcodeInject`       | 732       | `getPcodeInject`                      | 560-596  |
| 8 | `command_getcpoolref`      | `getCPoolRef`           | 751       | `getCPoolRef`                         | 605-620  |
| 9 | `command_getexternalref`   | `getExternalRef`        | 903       | `getExternalRef`                      | 329-344  |
|10 | `command_getmappedsymbols` | `getMappedSymbols`      | 788       | `getMappedSymbolsXML`                 | 305-320  |
|11 | `command_getnamespacepath` | `getNamespacePath`      | 802       | `getNamespacePath`                    | 353-368  |
|12 | `command_getpcode`         | `getPcode`              | 718       | `getPcode`                            | 281-296  |
|13 | `command_getregister`      | `getRegister`           | 676       | `getRegister`                         | 184-199  |
|14 | `command_getregistername`  | `getRegisterName`       | 693       | `getRegisterName`                     | 208-224  |
|15 | `command_getstringdata`    | `getStringData`         | 849       | `getStringData`                       | 504-541  |
|16 | `command_getcodelabel`     | `getCodeLabel`          | 911       | `getCodeLabel`                        | 395-410  |
|17 | `command_getdatatype`      | `getDataType`           | 867       | `getDataType`                         | 419-434  |
|18 | `command_gettrackedregisters`| `getTrackedRegisters` | 705       | `getTrackedRegisters`                 | 233-248  |
|19 | `command_getuseropname`    | `getUserOpName`         | 714       | `getUserOpName`                       | 257-272  |

That confirms exactly **19 callback commands**, fully cross-referenced
between the C++ caller and the Java responder.

### 4.1 Callback frame layout (general)

Decompiler -> host (one callback query):

```
type 4  (query open)
  type 14 (string open)
    PackedEncode <command name="command_getbytes" attr1=... attr2=.../>
  type 15 (string close)
type 5  (query close)
```

Host -> decompiler (one callback response, on success):

```
type 8  (query_response open)
  [optional payload — typically type 14/15 string with PackedEncode XML,
   or type 12/13 byte block, or nothing if "not found"]
type 9  (query_response close)
```

Host -> decompiler (on failure):

```
type 10 (exception open)
  type 14/15  exception class name
  type 14/15  exception message
type 11 (exception close)
```

This pattern is established by `ghidra_arch.cc:138-164`
(`readToResponse` / `readAll`).

### 4.2 Per-callback specifications

Per the framing convention I omit the literal type-4/type-5 wrapping in
the request bullets; assume every request is the PackedEncode element
named in the table, wrapped in string + query brackets. Likewise
responses are wrapped in `query_response_start`/`query_response_end`
(types 8 and 9).

For each callback I list:

- **When invoked:** what's happening in the decompiler that triggers it
- **Request:** PackedEncode element + attributes the decompiler sends
- **Response:** what bytes the host must write
- **Java impl:** one-line summary + cite
- **Rust difficulty:** L/M/H + why

#### 4.2.1 `command_getregister`
- **When:** during architecture initialisation, decompiler asks the host
  to translate a named register into a (space, offset, size) triple.
- **Request:** element with attribute `name` (string).
- **Response:** PackedEncode `<addr ...>` element describing the register
  storage. Empty response (just type 8 then 9) if unknown.
- **Java impl:** `getRegister()` at `DecompileProcess.java:676-684`
  calls `callback.getRegister(name)` which consults the Language object.
- **Rust difficulty: M.** Need to read `.pspec`/SLEIGH register listing.
  No external Ghidra API needed if pspec files are shipped.

#### 4.2.2 `command_getregistername`
- **When:** reverse lookup — decompiler has an address + size and wants
  the canonical name.
- **Request:** `<addr space=... offset=.../>` + `size` (signed int).
- **Response:** plain string in a `string_start`/`string_end` frame
  inside `query_response_start`/`query_response_end`.
- **Java impl:** `getRegisterName()` at `DecompileProcess.java:693-703`.
- **Rust difficulty: M.** Same data source as `getregister`.

#### 4.2.3 `command_gettrackedregisters`
- **When:** at the start of decompiling each function, decompiler asks
  for any register values that the program-analysis frontend believes
  are constant at the function entry (e.g. the `gs` segment selector,
  or a static `r0` value on ARM).
- **Request:** address (entry point).
- **Response:** PackedEncode `<tracked_pointset>` element. Empty is
  legal and common.
- **Java impl:** `getTrackedRegisters()` at `DecompileProcess.java:705-712`.
- **Rust difficulty: L.** Returning an empty list is valid for MVP.

#### 4.2.4 `command_getuseropname`
- **When:** decompiler encounters a user-defined p-code op (CALLOTHER
  with an index) and needs its symbolic name.
- **Request:** `index` (signed int).
- **Response:** plain string. Empty string if unknown.
- **Java impl:** `getUserOpName()` at `DecompileProcess.java:714-722`.
- **Rust difficulty: L.** Empty string is acceptable for trivial code
  that contains no CALLOTHER ops.

#### 4.2.5 `command_getpcode`
- **When:** decompiler wants the p-code translation of a single
  instruction (or instruction group) at a given address.
- **Request:** address.
- **Response:** PackedEncode element describing one or more p-code ops,
  each with input/output varnodes.
- **Java impl:** `getPcode()` at `DecompileProcess.java:718-725`
  invokes the SLEIGH translator on demand. **This is where SLEIGH
  actually fires** — the decompiler doesn't disassemble; it asks the
  host to.
- **Rust difficulty: H.** Either
  - (a) ship a Rust SLEIGH implementation (large effort), or
  - (b) shell out to a Ghidra subprocess just for this callback (defeats
    the purpose), or
  - (c) pre-translate p-code for the whole function before decompile
    starts (feasible because functions are bounded). This is the
    pragmatic path: have ghidra-cli pre-extract per-function p-code via
    its existing Java bridge and serve it from a cache.
- **This is the biggest blocker for Phase 3.**

#### 4.2.6 `command_getmappedsymbols`
- **When:** decompiler resolves an absolute address that looks like
  data — wants to know if there's a symbol, function, or "hole" there.
- **Request:** address.
- **Response:** PackedEncode element — one of `<symbol>`, `<function>`,
  or `<hole>` (the latter describing an unmapped range so the decompiler
  won't ask again).
- **Java impl:** `getMappedSymbols()` at `DecompileProcess.java:788-797`.
- **Rust difficulty: M.** Needs symbol table access. ghidra-cli already
  has `list-symbols`/`list-functions`; can be cached.

#### 4.2.7 `command_getexternalref`
- **When:** call target falls into an external (PLT/import) range.
- **Request:** address.
- **Response:** PackedEncode `<function>` (resolved external) or
  `<hole>` (unknown).
- **Java impl:** `getExternalRef()` at `DecompileProcess.java:903-...`.
- **Rust difficulty: M.** Imports table parsing in ghidra-cli.

#### 4.2.8 `command_getnamespacepath`
- **When:** decompiler is rendering a symbol and wants its fully
  qualified namespace.
- **Request:** namespace id (uint8 — actually a Ghidra-internal long
  carried over the wire).
- **Response:** PackedEncode `<parent>` element with chained `<val>`
  children naming each scope.
- **Java impl:** `getNamespacePath()` at `DecompileProcess.java:802-...`.
- **Rust difficulty: L.** Return `<parent><val name="Global"/></parent>`
  always-default for MVP.

#### 4.2.9 `command_isnameused`
- **When:** decompiler is choosing a variable name and wants to avoid
  collisions with existing symbols.
- **Request:** `name`, `startId`, `stopId`.
- **Response:** single character `'t'` or `'f'` in a string frame.
- **Java impl:** `isNameUsed()` at `DecompileProcess.java:920-...`.
- **Rust difficulty: L.** Return `'f'` always for MVP (only causes
  cosmetic naming clashes, not incorrect output).

#### 4.2.10 `command_getcodelabel`
- **When:** decompiler is rendering a jump target and wants a label.
- **Request:** address.
- **Response:** plain string (label name) or empty.
- **Java impl:** `getCodeLabel()` at `DecompileProcess.java:911-...`.
- **Rust difficulty: L.** Empty string works; decompiler will fall back
  to `LAB_<hex>` style.

#### 4.2.11 `command_getdatatype`
- **When:** decompiler needs the full structural form of a named or
  id'd data type (struct, typedef, enum...).
- **Request:** `name` (string), `id` (uint8 — actually long).
- **Response:** PackedEncode `<type>` element. Empty if not found.
- **Java impl:** `getDataType()` at `DecompileProcess.java:867-876`.
- **Rust difficulty: M.** For MVP returning empty is safe — types will
  default to primitive int/ptr. ghidra-cli has a type database, can be
  wired in.

#### 4.2.12 `command_getcomments`
- **When:** decompiler is annotating output with user comments.
- **Request:** `flags` (uint4 selecting comment types), `address`.
- **Response:** PackedEncode `<commentdb>` with zero or more `<comment>`
  children.
- **Java impl:** `getComments()` at `DecompileProcess.java:863-...`.
- **Rust difficulty: L.** Empty commentdb is fine for MVP.

#### 4.2.13 `command_getbytes`
- **When:** decompiler reads program memory (instruction bytes, constant
  pool, static data...).
- **Request:** `addr`, `size`.
- **Response:** byte stream framed in `byte_start`/`byte_end` (types 12
  and 13). Encoded with the **A-P nibble encoding** described in section
  2.2. Empty result encoded as zero-length byte block (or omitted
  entirely per Java side).
- **Java impl:** `getBytes()` at `DecompileProcess.java:879-896`.
- **Rust difficulty: L.** Need to read raw bytes from program file at a
  given virtual address. ghidra-cli already exposes this via
  `read-memory`.

#### 4.2.14 `command_getstringdata`
- **When:** decompiler dereferences a pointer to what looks like a
  string literal and wants the bytes.
- **Request:** `maxBytes`, type name, type id, address.
- **Response:** A-P-encoded bytes plus a truncation flag.
- **Java impl:** `getStringData()` at `DecompileProcess.java:849-...`.
- **Rust difficulty: L.** Same memory access as `getBytes`. Truncation
  flag is straightforward.

#### 4.2.15 `command_getcallfixup`, `command_getcallotherfixup`, `command_getcallmech`, `command_getpcodeexecutable`
- All four route to the same Java method (`getPcodeInject`,
  `DecompileProcess.java:732`) and the same C++ sender. They differ only
  in **which inject table** to consult:
  - `callfixup` — user-defined replacements for whole call sites
  - `callotherfixup` — replacements for CALLOTHER (userop) instructions
  - `callmech` — calling-convention prologue/epilogue p-code
  - `pcodeexecutable` — directly executable p-code (rare)
- **Request:** inject `name` + `InjectContext` (PackedEncode element
  with calling convention, address, parameter list).
- **Response:** PackedEncode `<inst>` element with child `<op>` p-code
  ops.
- **Java impl:** `getPcodeInject()` at `DecompileProcess.java:732-...`.
- **Rust difficulty: H** in general, **L** for MVP: return empty/no-op
  injection for all four. The decompiler will produce slightly less
  idiomatic output for prologue/epilogue but will still decompile.

#### 4.2.16 `command_getcpoolref`
- **When:** decompiler hits a class-file constant pool reference (Java
  bytecode / .class targets).
- **Request:** array of integer ids forming a constant pool reference.
- **Response:** PackedEncode constant pool record.
- **Java impl:** `getCPoolRef()` at `DecompileProcess.java:751-...`.
- **Rust difficulty: L for native x86_64.** Constant pools are a JVM
  concept. Return empty / unsupported. Irrelevant to native code.

---

## 5. Minimum viable subset (MVS) for E7.2

For decompiling a trivial native x86_64 function such as:

```c
int f(void) { return 0; }
```

the Rust host needs:

### 5.1 Top-level commands (host -> decompiler)

| Cmd | Must implement | Notes |
|-----|----------------|-------|
| `registerProgram`   | **Yes**          | Cannot proceed without it. Ship hardcoded x86-64 pspec/cspec/tspec/core types. |
| `setAction`         | **Yes**          | At least `("decompile","c-language")`. |
| `setOptions`        | Optional         | Defaults are fine. |
| `decompileAt`       | **Yes**          | The whole point. |
| `flushNative`       | Optional         | Only needed across program edits. |
| `structureGraph`    | No               | Skip. |
| `deregisterProgram` | Optional         | Pure cleanliness — process can just exit. |

### 5.2 Callback queries (host -> respond to decompiler)

For a trivial-function decompile the decompiler will issue **at least**
these callbacks. The host MUST answer each. Empty/default answers
suffice for many.

| Callback                    | MVS behaviour                                             |
|-----------------------------|-----------------------------------------------------------|
| `command_getregister`       | Honest answer required (resolve named registers).         |
| `command_getregistername`   | Honest answer required.                                   |
| `command_gettrackedregisters` | Empty `<tracked_pointset/>` is acceptable.              |
| `command_getuseropname`     | Empty string ok (no CALLOTHER in trivial code).           |
| `command_getpcode`          | **Honest answer required — biggest hurdle.** See 4.2.5.   |
| `command_getmappedsymbols`  | Return `<hole>` for unknown addresses; honest `<function>` at the entry. |
| `command_getexternalref`    | Return `<hole>`.                                          |
| `command_getnamespacepath`  | Return `<parent><val name="Global"/></parent>`.           |
| `command_isnameused`        | Always `'f'`.                                             |
| `command_getcodelabel`      | Empty string.                                             |
| `command_getdatatype`       | Empty for MVP — primitive int/void are built in.          |
| `command_getcomments`       | Empty `<commentdb/>`.                                     |
| `command_getbytes`          | **Honest answer required** — return real bytes.           |
| `command_getstringdata`     | Empty / not-string.                                       |
| `command_getcallfixup`      | Empty inject.                                             |
| `command_getcallotherfixup` | Empty inject.                                             |
| `command_getcallmech`       | Empty inject (default conventions still work).            |
| `command_getpcodeexecutable`| Empty inject.                                             |
| `command_getcpoolref`       | Empty record (not relevant to native).                    |

**Net effect:** 4 callbacks need real implementations
(`getregister`, `getregistername`, `getpcode`, `getbytes`); the other
15 can be stubbed to return empty/default values for the first
round-trip. **The one hard one is `getpcode`.**

---

## 6. Risks and unknowns

### 6.1 The hidden hard dependency: `command_getpcode`

The decompiler is *not* a disassembler. It asks the host for p-code per
instruction. That means a Rust host has to either implement (or wrap)
SLEIGH. There is no cheap path. Options:

- **(P1, recommended for spike)** Use the existing Java bridge in
  ghidra-cli to pre-extract p-code for the target function, persist it,
  and serve it from the Rust host's cache. This lets us prove the
  round-trip in Phase 3 without writing a SLEIGH implementation.
- **(P2)** Port a subset of SLEIGH to Rust (x86_64 only). Months of work.
- **(P3)** Vendor the SLEIGH C++ implementation alongside the decompiler
  and link it into the Rust host. Architecturally awkward.

This is by far the biggest blocker. **Mention it in the issue.**

### 6.2 PackedEncode/PackedDecode parity

Both directions assume both sides implement the same binary encoding of
attributed XML elements (PackedEncode). The Rust host has to read **and**
write this format. Reference is
`Ghidra/Features/Decompiler/src/decompile/cpp/marshal.{hh,cc}`. Plan a
small `ghidra-packed-marshal` crate.

### 6.3 Version drift

The protocol is undocumented and internal. The constants in
`DecompileProcess.java:38-46` and the command-name strings in
`ghidra_arch.cc` could change between Ghidra releases. The wire format
is **not** versioned on the wire. Mitigation:

- Pin to a specific Ghidra release in CI.
- Add a smoke test that exercises the full callback set.
- Don't ship a Rust host that targets `master`; target the latest
  stable Ghidra tag.

### 6.4 The 4-byte sentinel is not robust against zero bytes in payloads

Inside `byte_start`/`byte_end` Ghidra dodges this with the A-P encoding.
Inside `string_start`/`string_end` they dodge it with PackedEncode's
self-escaping. Anywhere else, raw zero bytes will be misread. A Rust
host must never emit raw `0x00 0x00 0x01 ??` outside of a marker.

### 6.5 Read-until-burst is greedy

`readToAnyBurst` silently consumes any leading garbage. If the host
mis-frames a response, the decompiler will skip past it and look for
the next burst — symptoms can appear arbitrarily later in the protocol
than the actual bug. **Logging both sides verbatim is essential during
bring-up.**

### 6.6 No per-callback length-prefix

There is no way to "skip" an unfamiliar callback without parsing its
payload to find the close marker. A future Ghidra version that adds a
20th callback will be silently misinterpreted by the host. Mitigation:
the host should log unknown command names loudly and emit an
exception_start/exception_end pair to fail fast rather than try to
recover.

### 6.7 Threading / re-entrancy

The decompiler is single-threaded over the pipe. The Rust host must not
issue a second top-level command until the first one has fully
completed (including all callback round-trips). This is easy to mess up
if the host runs an async runtime — funnel everything through a single
owning task.

### 6.8 Deceptive simplicity

The fact that there are "only" 19 callbacks understates the work. Two
of them (`getpcode` and `getmappedsymbols`) carry the bulk of the
semantic load; everything else is administrative. A naive count makes
the project look 5x easier than it is.

---

## 7. Key findings

### 7.1 Wire format reality

The protocol is a self-synchronising byte stream with 4-byte alignment
bursts (`0x00 0x00 0x01 <type>`). There are 16 type codes. Strings
carry PackedEncode binary XML; raw bytes use a custom A-P nibble
encoding to avoid clashing with the sentinel. There is no length
prefix, no version field, and no schema. The Java implementation in
`DecompileProcess.java` (constants at lines 38-46, dispatch at
436-510) is the only authoritative reference.

### 7.2 What blocks Phase 3 hardest

`command_getpcode` (`DecompileProcess.java:718-725`,
`ghidra_arch.cc:281-296`). The decompiler delegates *all* instruction
decoding to its host. A pure Rust host therefore either has to embed
SLEIGH (large) or pre-compute p-code via ghidra-cli's existing Java
bridge and cache it (pragmatic). Everything else in the spec is
tractable; this one item is order-of-magnitude harder than the rest
combined.

### 7.3 Smallest stub-host that round-trips for E7.2

Aim: spawn the upstream `decompile` binary, register a hand-built
x86-64 program, decompile one trivial function, get back a
PackedEncode `<doc>` element. Required Rust pieces:

1. A PackedEncode reader+writer (small crate, ~1k lines).
2. The 16 frame-marker constants and a streaming framer.
3. Hardcoded pspec/cspec/tspec/coretypes for x86-64 GCC (lifted from
   `Ghidra/Processors/x86/data/languages/`).
4. The seven top-level commands (only `registerProgram`, `setAction`,
   `decompileAt` need work; the others can be stubs).
5. **Stubs for 15 of the 19 callbacks** returning empty/default
   PackedEncode elements.
6. Real implementations of `command_getbytes` (read from program
   binary), `command_getregister` and `command_getregistername`
   (resolve against the pspec), and `command_getpcode`.
7. For `command_getpcode`, the spike implementation should **shell
   out to ghidra-cli's existing Java bridge** to fetch p-code per
   address, populate an in-memory cache, and serve from there. This
   defers the SLEIGH-in-Rust question to Phase 4 while still proving
   that the Rust host correctly speaks the protocol.

If steps 1-6 plus a Java-bridge-backed `getpcode` succeed in producing
a `<doc>` element containing C source for `int f(){return 0;}`, the
Phase 3 protocol round-trip is proven.

---

## Appendix A: file map for follow-up reads

All paths relative to `NationalSecurityAgency/ghidra@master`:

- `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileProcess.java` — Java host (the file to replace).
- `Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_process.cc` — C++ child main loop and top-level command handlers.
- `Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc` — C++ side of all 19 callbacks (`ArchitectureGhidra::...`).
- `Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_translate.cc` — C++ wrapper that uses `getpcode` to synthesise a `Translate` object.
- `Ghidra/Features/Decompiler/src/decompile/cpp/marshal.{hh,cc}` — PackedEncode/PackedDecode binary XML format.
- `Ghidra/Processors/x86/data/languages/x86-64.pspec` (+ `.cspec`, `.ldefs`) — content needed for `registerProgram`.
- `Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/DecompileCallback.java` — the Java callback interface that delegates everything to a live `Program` (good shopping list of "what real data a callback needs").
