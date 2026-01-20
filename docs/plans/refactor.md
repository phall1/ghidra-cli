
Based on the code you uploaded, the current architecture is a **"One-Shot Headless"** model. Every time a query runs, the CLI (or Daemon) spawns a new `analyzeHeadless` process, initializes the JVM, loads the project, runs a script, and shuts down.

This is robust in terms of isolation (if it crashes, it doesn't affect the next run), but it is **slow** (high latency due to JVM startup) and **fragile** (parsing `stdout` mixed with Ghidra logs).

Here is a roadmap to make the CLI significantly more robust and deeply integrated with the IDE.

---

### Part 1: Improving Robustness (The "Persistent Bridge" Architecture)

To make this robust, you need to move from "Spawn Process -> Parse Stdout" to "Spawn Process -> Connect via Socket -> Keep Alive". This prevents the overhead of restarting Ghidra for every command.

#### 1. Create a "Ghidra Bridge" Python Script

Instead of many small scripts (`get_list_functions.py`, etc.), create one master Python script that runs an infinite loop inside Ghidra (Headless or GUI) and listens for JSON commands.

**File:** `src/ghidra/scripts/bridge.py` (New file)

```python
# @category Bridge
# @keybinding
# @menupath Tools.Start CLI Bridge
# @toolbar

import socket
import json
import threading
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

# Define your command handlers here
def handle_functions(args):
    # ... (Logic from your existing get_list_functions_script)
    return [{"name": "example", "addr": "0x1234"}]

def handle_decompile(args):
    # ... (Logic from your existing decompile script)
    return {"code": "int main() { ... }"}

COMMANDS = {
    "functions": handle_functions,
    "decompile": handle_decompile
}

def start_server(port=12345):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(1)
    print(json.dumps({"status": "ready", "port": port}))

    while True:
        conn, addr = s.accept()
        try:
            # Read line-based JSON
            f = conn.makefile()
            while True:
                line = f.readline()
                if not line: break
                
                try:
                    req = json.loads(line)
                    cmd = req.get("command")
                    args = req.get("args", {})
                    
                    if cmd in COMMANDS:
                        result = COMMANDS[cmd](args)
                        response = {"status": "success", "data": result}
                    else:
                        response = {"status": "error", "message": "Unknown command"}
                        
                    conn.sendall(json.dumps(response) + "\n")
                except Exception as e:
                    conn.sendall(json.dumps({"status": "error", "message": str(e)}) + "\n")
        except:
            pass
        finally:
            conn.close()

if __name__ == "__main__":
    # If running in GUI, run in background thread to not freeze UI
    if isRunningHeadless():
        start_server()
    else:
        t = threading.Thread(target=start_server)
        t.start()

```

#### 2. Update `HeadlessExecutor` to manage a Lifecycle

Modify `src/ghidra/headless.rs` or `src/daemon/process.rs`. Instead of just `Command::new()`, you need a struct that holds the `Child` process and a `TcpStream`.

* **Startup:** Spawn `analyzeHeadless` with the `bridge.py` script.
* **Handshake:** Wait for the specific JSON `{"status": "ready"}` on stdout.
* **Execution:** Connect to the port via TCP. Send requests as JSON lines.
* **Cleanup:** Kill the child process on daemon shutdown.

This eliminates `stdout` parsing issues because data transfer happens over a clean TCP socket.

---

### Part 2: Better IDE Integration (Bi-directional Control)

Currently, your CLI talks to a headless instance. The user wants to see results in the GUI.

#### 1. Shared Project Locking

Ghidra does not allow a Headless instance and a GUI instance to have write access to the same project simultaneously.

* **Robustness Fix:** The CLI should detect if the GUI is open.
* **Strategy:** If the GUI is open, the CLI should **not** spawn a headless instance. Instead, it should connect to the *Bridge* running inside the GUI.

#### 2. Context Synchronization (CLI -> GUI)

Add commands to the Bridge script that manipulate the GUI state.

**Update `bridge.py`:**

```python
def handle_goto(args):
    addr_str = args.get("address")
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    
    # Check if we are in GUI mode
    if not isRunningHeadless():
        from ghidra.framework.plugintool import PluginTool
        state = state # Ghidra injects 'state'
        tool = state.getTool()
        if tool:
            tool.firePluginEvent(...) # Or simpler:
            # This often requires the script to be run via the Ghidra Script Manager
            currentLocation = ProgramLocation(currentProgram, addr)
            tool.setGoTo(currentLocation)
    return {"status": "moved"}

def handle_highlight(args):
    # Set background color of address range
    if not isRunningHeadless():
        setBackgroundColor(addr, Color.RED)

```

**Update Rust CLI (`src/cli.rs`):**
Add a command `ghidra focus <address>` which sends the `goto` command to the bridge.

#### 3. Automatic Discovery

How does the CLI know if the GUI is running?

1. **Port Scanning:** The Rust CLI can try to connect to the default Bridge port (e.g., 12345).
2. **Logic:**
* Try `TcpStream::connect("127.0.0.1:12345")`.
* If successful -> **GUI Mode**. Send commands there.
* If failed -> **Headless Mode**. Check if Daemon is running. If not, start Daemon (which spawns Headless Bridge).



---

### Part 3: Robustness Improvements in Rust

#### 1. Fix Output Parsing (`src/ghidra/headless.rs`)

Your current `extract_json_from_output` relies on counting braces. This is risky if the program being analyzed contains strings with braces.

**Improved approach (if not using Bridge):**
Wrap the output in a unique delimiter in the Python script.

*Python Script:*

```python
print("---GHIDRA_CLI_START---")
print(json.dumps(data))
print("---GHIDRA_CLI_END---")

```

*Rust (`headless.rs`):*

```rust
fn extract_json_from_output(&self, output: &str) -> Result<String> {
    let start_marker = "---GHIDRA_CLI_START---";
    let end_marker = "---GHIDRA_CLI_END---";
    
    let start = output.find(start_marker)
        .ok_or(GhidraError::ExecutionFailed("Missing start marker".into()))? 
        + start_marker.len();
        
    let end = output.find(end_marker)
        .ok_or(GhidraError::ExecutionFailed("Missing end marker".into()))?;
        
    Ok(output[start..end].trim().to_string())
}

```

#### 2. Typed Responses with `serde`

In `src/ghidra/data.rs`, strictly enforce optionals. If Ghidra scripts fail (e.g., decompilation error), they should return a standard error object.

```rust
#[derive(Deserialize)]
#[serde(tag = "status")]
enum BridgeResponse<T> {
    #[serde(rename = "success")]
    Success { data: T },
    #[serde(rename = "error")]
    Error { message: String },
}

```

Update `src/daemon/queue.rs` to parse this wrapper before returning the inner string.

---

### Part 4: Implementation Plan

Here is the recommended order of operations to upgrade your tool:

1. **Implement the Bridge Script:** Create `scripts/ghidra_bridge.py`.
2. **Update Daemon to support "Long-Running" Process:**
* Modify `DaemonState` to hold a `Child` process handle.
* Modify `HeadlessExecutor` to check if the bridge is up; if so, use TCP; if not, spawn it.


3. **Add GUI Commands:** Add `goto`, `highlight`, and `select` to the bridge and `src/cli.rs`.
4. **Integration Test:** Open Ghidra GUI, run the bridge script manually. Then run `ghidra query functions` from your terminal. It should return results instantly using the GUI's memory.

This transforms your tool from a "Batch Processor" to a "Live Assistant."