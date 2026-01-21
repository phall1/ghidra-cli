# Ghidra CLI Bridge Script
# @category Bridge
# @keybinding
# @menupath Tools.Start CLI Bridge
# @toolbar
#
# This script runs a persistent TCP server inside Ghidra to serve CLI commands.
# It keeps Ghidra loaded in memory for fast command execution.

import socket
import json
import threading
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

# Default bridge port
BRIDGE_PORT = 18700

# --- Command Handlers ---

def handle_ping(args):
    """Health check."""
    return {"message": "pong"}

def handle_program_info(args):
    """Get current program information."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    info = {
        "name": currentProgram.getName(),
        "executable_path": currentProgram.getExecutablePath(),
        "executable_format": currentProgram.getExecutableFormat(),
        "compiler": currentProgram.getCompiler() if currentProgram.getCompiler() else None,
        "language": str(currentProgram.getLanguage()),
        "image_base": str(currentProgram.getImageBase()),
        "min_address": str(currentProgram.getMinAddress()),
        "max_address": str(currentProgram.getMaxAddress())
    }
    
    function_manager = currentProgram.getFunctionManager()
    info["function_count"] = function_manager.getFunctionCount()
    
    return info

def handle_list_functions(args):
    """List all functions in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    limit = args.get("limit")
    name_filter = args.get("filter")
    
    functions = []
    function_manager = currentProgram.getFunctionManager()
    count = 0
    
    for func in function_manager.getFunctions(True):
        if limit and count >= limit:
            break
            
        name = func.getName()
        if name_filter and name_filter.lower() not in name.lower():
            continue
            
        entry = func.getEntryPoint()
        body = func.getBody()
        
        func_data = {
            "name": name,
            "address": str(entry),
            "size": body.getNumAddresses(),
            "entry_point": str(entry),
            "signature": func.getPrototypeString(False, False) if func.getSignature() else None,
            "calling_convention": func.getCallingConventionName(),
            "comment": func.getComment()
        }
        
        functions.append(func_data)
        count += 1
    
    return {"functions": functions, "count": len(functions)}

def handle_decompile(args):
    """Decompile a function at the given address."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    addr_str = args.get("address")
    if not addr_str:
        return {"error": "No address provided"}
    
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return {"error": "Invalid address: " + addr_str}
    
    function_manager = currentProgram.getFunctionManager()
    func = function_manager.getFunctionContaining(addr)
    
    if not func:
        return {"error": "No function at address " + addr_str}
    
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    monitor = ConsoleTaskMonitor()
    results = decompiler.decompileFunction(func, 30, monitor)
    
    if results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": func.getPrototypeString(False, False),
            "code": code
        }
    else:
        return {"error": "Decompilation failed"}

def handle_list_strings(args):
    """List all strings in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    limit = args.get("limit")
    
    strings = []
    listing = currentProgram.getListing()
    data_iterator = listing.getDefinedData(True)
    count = 0
    
    while data_iterator.hasNext():
        if limit and count >= limit:
            break
            
        data = data_iterator.next()
        if data.hasStringValue():
            try:
                string_val = str(data.getValue())
                string_data = {
                    "address": str(data.getAddress()),
                    "value": string_val,
                    "length": len(string_val)
                }
                strings.append(string_data)
                count += 1
            except Exception:
                pass
    
    return {"strings": strings, "count": len(strings)}

def handle_list_imports(args):
    """List all imports in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    imports = []
    symbol_table = currentProgram.getSymbolTable()
    external_manager = currentProgram.getExternalManager()
    
    for symbol in symbol_table.getExternalSymbols():
        external_location = external_manager.getExternalLocation(symbol)
        
        if external_location:
            import_data = {
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "library": external_location.getLibraryName()
            }
            imports.append(import_data)
    
    return {"imports": imports, "count": len(imports)}

def handle_list_exports(args):
    """List all exports in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    exports = []
    symbol_table = currentProgram.getSymbolTable()
    
    for symbol in symbol_table.getSymbolIterator():
        if symbol.isExternalEntryPoint():
            export_data = {
                "name": symbol.getName(),
                "address": str(symbol.getAddress())
            }
            exports.append(export_data)
    
    return {"exports": exports, "count": len(exports)}

def handle_memory_map(args):
    """Get memory map."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    blocks = []
    memory = currentProgram.getMemory()
    
    for block in memory.getBlocks():
        perms = ""
        if block.isRead():
            perms += "r"
        if block.isWrite():
            perms += "w"
        if block.isExecute():
            perms += "x"
        
        block_data = {
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": perms,
            "is_initialized": block.isInitialized(),
            "is_loaded": block.isLoaded()
        }
        blocks.append(block_data)
    
    return {"blocks": blocks, "count": len(blocks)}

def handle_xrefs_to(args):
    """Get cross-references to an address."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    addr_str = args.get("address")
    if not addr_str:
        return {"error": "No address provided"}
    
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return {"error": "Invalid address: " + addr_str}
    
    xrefs = []
    refs = currentProgram.getReferenceManager().getReferencesTo(addr)
    function_manager = currentProgram.getFunctionManager()
    
    for ref in refs:
        from_addr = ref.getFromAddress()
        from_func = function_manager.getFunctionContaining(from_addr)
        to_func = function_manager.getFunctionContaining(addr)
        
        xref_data = {
            "from": str(from_addr),
            "to": str(addr),
            "ref_type": str(ref.getReferenceType()),
            "from_function": from_func.getName() if from_func else None,
            "to_function": to_func.getName() if to_func else None
        }
        xrefs.append(xref_data)
    
    return {"xrefs": xrefs, "count": len(xrefs)}

def handle_xrefs_from(args):
    """Get cross-references from an address."""
    if currentProgram is None:
        return {"error": "No program loaded"}
    
    addr_str = args.get("address")
    if not addr_str:
        return {"error": "No address provided"}
    
    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        return {"error": "Invalid address: " + addr_str}
    
    xrefs = []
    refs = currentProgram.getReferenceManager().getReferencesFrom(addr)
    function_manager = currentProgram.getFunctionManager()
    
    for ref in refs:
        to_addr = ref.getToAddress()
        from_func = function_manager.getFunctionContaining(addr)
        to_func = function_manager.getFunctionContaining(to_addr)
        
        xref_data = {
            "from": str(addr),
            "to": str(to_addr),
            "ref_type": str(ref.getReferenceType()),
            "from_function": from_func.getName() if from_func else None,
            "to_function": to_func.getName() if to_func else None
        }
        xrefs.append(xref_data)
    
    return {"xrefs": xrefs, "count": len(xrefs)}

# --- Command Router ---

COMMANDS = {
    "ping": handle_ping,
    "program_info": handle_program_info,
    "list_functions": handle_list_functions,
    "decompile": handle_decompile,
    "list_strings": handle_list_strings,
    "list_imports": handle_list_imports,
    "list_exports": handle_list_exports,
    "memory_map": handle_memory_map,
    "xrefs_to": handle_xrefs_to,
    "xrefs_from": handle_xrefs_from,
}

# --- Server Logic ---

def handle_request(line):
    """Parse and handle a single JSON request."""
    try:
        req = json.loads(line)
        cmd = req.get("command")
        args = req.get("args", {})
        
        if cmd == "shutdown":
            return {"status": "shutdown"}, True
        
        if cmd in COMMANDS:
            result = COMMANDS[cmd](args)
            if "error" in result:
                return {"status": "error", "message": result["error"]}, False
            return {"status": "success", "data": result}, False
        else:
            return {"status": "error", "message": "Unknown command: " + str(cmd)}, False
            
    except Exception as e:
        return {"status": "error", "message": str(e)}, False

def start_server(port=BRIDGE_PORT):
    """Start the bridge server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(1)
    
    # Signal ready to the parent process
    print("---GHIDRA_CLI_START---")
    print(json.dumps({"status": "ready", "port": port}))
    print("---GHIDRA_CLI_END---")
    
    running = True
    while running:
        try:
            conn, addr = s.accept()
            f = conn.makefile('r')
            out = conn.makefile('w')
            
            try:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    response, should_shutdown = handle_request(line.strip())
                    out.write(json.dumps(response) + "\n")
                    out.flush()
                    
                    if should_shutdown:
                        running = False
                        break
            finally:
                f.close()
                out.close()
                conn.close()
                
        except Exception as e:
            print("Bridge error: " + str(e))
    
    s.close()

# --- Entry Point ---

if __name__ == "__main__" or True:  # Also runs when sourced by Ghidra
    # Determine port from args if provided
    port = BRIDGE_PORT
    if 'args' in dir() and len(args) > 0:
        try:
            port = int(args[0])
        except:
            pass
    
    # If running in GUI, run in background thread to not freeze UI
    if 'isRunningHeadless' in dir() and isRunningHeadless():
        start_server(port)
    else:
        # GUI mode - run in background thread
        t = threading.Thread(target=start_server, args=(port,))
        t.daemon = True
        t.start()
        print("Bridge started in background on port " + str(port))
