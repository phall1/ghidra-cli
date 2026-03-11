# Reverse Engineering Design and Spec

## Scope

- Primary completed target: `/usr/bin/openssl`
- Deferred/triaged target: `/Users/phall/.local/bin/claude` (Bun-embedded runtime binary)
- Tooling: `ghidra-cli` (`import`, `analyze`, `dump`, `find`, `decompile`)

## Executive Summary

`/usr/bin/openssl` is a monolithic, table-driven CLI executable that initializes OpenSSL and BIO subsystems, loads configuration, resolves subcommands via a sorted function table + hash lookup, and dispatches into command-specific handlers (for example `enc`, `s_client`, `s_server`, `x509`, `speed`).

The architecture is cleanly separable into:

1. Startup and global initialization
2. Command registration and dispatch
3. Shared argument parsing framework
4. Command-specific execution pipelines (crypto, TLS, PKI, utility commands)
5. Global teardown and cleanup

## Binary Profile

- Path: `/usr/bin/openssl`
- SHA-256: `596112057e5aac725c0a9b0fd96c97c581b0a1b8d453670d02f07cb240afb5bb`
- Format: Mach-O universal binary (`x86_64`, `arm64e`)
- Analyzed slice in this project: `x86_64` (`x86/little/64/default`)
- Ghidra stats:
  - Functions: `2471`
  - Exports: `155`
  - Imports: `1049`
  - Strings: `6060`
  - Instructions: `52276`
  - Sections: `18`

## Top-Level Architecture

### 1) Startup and Runtime Initialization

Entry function (`_main` / `entry`, address `0x10001873f`) performs:

- Error/output channel setup (`_bio_err = BIO_new_fp(stderr, ...)`)
- Socket subsystem init (`BIO_sock_init`)
- Core OpenSSL init (`OPENSSL_add_all_algorithms_noconf`, `SSL_library_init`, `SSL_load_error_strings`)
- UI hooks setup (`setup_ui`)
- Config resolution and load:
  - prefers `OPENSSL_CONF`
  - else uses generated default config name
  - `NCONF_load` + `load_config`

### 2) Command Registry and Dispatch

The binary exports a command registry table at `_functions` (`0x100059000`) containing command names and handler pointers.

Dispatch flow in `_main`:

- `qsort(_functions, ..., SortFnByName)`
- build LHASH index (`lh_new`, `lh_insert`)
- derive invoked program/command name
- `lh_retrieve` command metadata
- dispatch via function pointer

If no explicit command is supplied (`argc == 1`), it enters interactive shell mode and repeatedly parses and executes commands from stdin.

### 3) Shared Option Parsing Framework

`_options_parse` is a shared parser used by command handlers.

Traits:

- table-driven option descriptors
- typed handlers (string, integer, long, callback, bit flags)
- argument count and type validation
- uniform missing-arg/unknown-option diagnostics

This strongly indicates a common CLI framework layered under each command-specific handler.

## Detailed Command Pipeline Specs

### A) `enc` Command (`_enc_main`, `0x100013591`)

#### Purpose

Symmetric encryption/decryption pipeline for file/stream inputs, with configurable cipher, digest, key derivation, salt, IV, and optional base64 wrapping.

#### Control Flow

1. Identify command mode and cipher (`EVP_get_cipherbyname`)
2. Parse arguments (`_options_parse` with `_enc_options`)
3. Build BIO input/output chain
4. Resolve KDF and key/IV source
5. Configure `EVP_CIPHER_CTX` via `EVP_CipherInit_ex`
6. Stream transform loop (`BIO_read` -> `BIO_write`)
7. Flush/finalize and cleanup

#### Key Derivation Modes

- Legacy path: `EVP_BytesToKey`
- PBKDF2 path: `PKCS5_PBKDF2_HMAC`
  - observed default iteration baseline is set to `10000` when PBKDF2 mode is enabled and explicit iteration not provided

#### Salt/IV/Key Handling

- Supports explicit hex key/IV parsing (`_set_hex`)
- Supports password prompt/file/pass source flows (`_app_passwd`)
- Supports `Salted__` header read/write behavior for compatible salted format
- Can print `salt/key/iv` under debug-style option paths

#### Dataflow (Simplified)

`input BIO` -> `[optional base64 BIO]` -> `[cipher BIO]` -> `output BIO`

### B) TLS Client (`s_client`) (`_s_client_main`, `0x100022444`)

#### Purpose

Interactive and scripted TLS client with protocol negotiation controls, certificate/key loading, STARTTLS adapters, and handshake/debug instrumentation.

#### Defaults and Config

- default host: `localhost`
- default port: `4433`
- default method: `TLS_client_method`

#### Setup Stages

1. Parse options (`_options_parse` with `_s_client_options`)
2. Parse host/port (`_extract_host_port`)
3. Optional credential load (`_load_key`, `_load_cert`)
4. Build `SSL_CTX` and apply:
   - min/max protocol bounds
   - ciphers and groups
   - ALPN settings
   - verify behavior and callback wiring
5. Establish socket via `_init_client`
6. Bind BIO/socket to SSL and set connect state
7. Handshake and stream loop using `poll` + `SSL_read`/`SSL_write`

#### STARTTLS and Transport Adaptors

Observed protocol upgrade logic for:

- SMTP
- POP3
- IMAP
- FTP
- XMPP
- Proxy CONNECT flow

#### Session and Reconnect Features

- session input/output file support (`sess_in`, `sess_out` paths)
- reconnect loop support
- optional verbose state/msg/tlsext callbacks for diagnostics

### C) Network Connect Helper (`_init_client`, `0x100027df1`)

`_init_client` uses:

- `getaddrinfo` resolution
- iterative `socket` + `connect` attempts over returned address list
- optional `SO_KEEPALIVE` on stream sockets
- explicit error diagnostics (`gai_strerror`, `perror`)

Returns success only after a valid connected socket is established.

## Command Surface Evidence

Exported command handlers include (partial):

- `_asn1parse_main`
- `_ca_main`
- `_cms_main`
- `_dgst_main`
- `_enc_main`
- `_ocsp_main`
- `_pkcs12_main`
- `_req_main`
- `_rsa_main`
- `_s_client_main`
- `_s_server_main`
- `_speed_main`
- `_verify_main`
- `_x509_main`

This confirms a broad multi-command utility architecture where each command maps to a dedicated handler function.

## Security-Relevant Observations

1. Legacy KDF path (`EVP_BytesToKey`) remains present in `enc` flow.
2. PBKDF2 path exists and is selectable; observed default iteration baseline is `10000` when enabled without explicit override.
3. `s_client` has extensive debugging and test toggles (expected for diagnostic utility); this is not a hardened pinned-policy client by default.
4. Key/IV/salt printing paths exist and must be treated as sensitive output when enabled.

## Why the Claude/Bun Target Was Deferred

`/Users/phall/.local/bin/claude` is a Bun-embedded runtime executable where static symbol and control-flow surfaces are dominated by engine/runtime internals rather than clean product-layer boundaries.

Observed effect in static RE:

- high volume of runtime scaffolding functions
- weak separation between app-specific and engine-specific execution paths
- decompilation yields low-signal architectural boundaries for product semantics

This is not a tooling impossibility; it is a methodology mismatch for static-only pass. For that target, a hybrid workflow is recommended: static triage + resource extraction + dynamic tracing.

## Reproduction Commands

```bash
./scripts/with-ghidra-env.sh target/debug/ghidra import "/usr/bin/openssl" --project openssl-re --program openssl
./scripts/with-ghidra-env.sh target/debug/ghidra analyze --project openssl-re --program openssl

./scripts/with-ghidra-env.sh target/debug/ghidra summary --project openssl-re --program openssl --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra stats --project openssl-re --program openssl --pretty
./scripts/with-ghidra-env.sh target/debug/ghidra dump exports --project openssl-re --program openssl --pretty

./scripts/with-ghidra-env.sh target/debug/ghidra decompile _main --project openssl-re --program openssl
./scripts/with-ghidra-env.sh target/debug/ghidra decompile _options_parse --project openssl-re --program openssl
./scripts/with-ghidra-env.sh target/debug/ghidra decompile _enc_main --project openssl-re --program openssl
./scripts/with-ghidra-env.sh target/debug/ghidra decompile _s_client_main --project openssl-re --program openssl
./scripts/with-ghidra-env.sh target/debug/ghidra decompile _init_client --project openssl-re --program openssl
```

## Confidence

- Startup, dispatch, options framework: high confidence (directly decompiled)
- `enc` crypto pipeline and KDF branch behavior: high confidence (directly decompiled)
- `s_client` handshake/event-loop/STARTTLS behavior: high confidence (directly decompiled)
- Fine-grained semantics of every option side-effect: medium (not all helper branches fully traced)
