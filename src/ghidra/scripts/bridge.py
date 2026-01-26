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
import sys
import os
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface

# Default bridge port
BRIDGE_PORT = 18700

# Global registry for Ghidra objects that imported modules can access
import builtins
builtins.currentProgram = currentProgram
try:
    builtins.currentAddress = currentAddress
except:
    builtins.currentAddress = None
try:
    builtins.currentLocation = currentLocation
except:
    builtins.currentLocation = None
try:
    builtins.state = state
except:
    builtins.state = None
try:
    builtins.monitor = monitor
except:
    builtins.monitor = None

# Helper to import modules with Ghidra globals injected
def import_ghidra_module(module_name):
    """Import a module - Ghidra globals are available via builtins."""
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Force reimport to get fresh module
    if module_name in sys.modules:
        del sys.modules[module_name]

    module = __import__(module_name)
    return module

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

def handle_program_close(args):
    """Close the current program."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    program_name = currentProgram.getName()
    state.getTool().closeProgram(currentProgram, False)

    return {"status": "closed", "program": program_name}

def handle_program_delete(args):
    """Delete a program from the project."""
    program_name = args.get("program")
    if not program_name:
        return {"error": "Program name required"}

    project = state.getProject()
    if project is None:
        return {"error": "No project open"}

    project_data = project.getProjectData()

    try:
        program_file = project_data.getFile(program_name)
        if program_file is None:
            return {"error": "Program not found: " + program_name}

        project_data.deleteFile(program_name)
        return {"status": "deleted", "program": program_name}
    except Exception as e:
        return {"error": "Failed to delete program: " + str(e)}

def handle_program_export(args):
    """Export program to specified format."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    export_format = args.get("format", "json")
    output_path = args.get("output")

    if export_format == "json":
        data = handle_program_info({})
        if "error" in data:
            return data

        function_manager = currentProgram.getFunctionManager()
        functions = []
        for func in function_manager.getFunctions(True):
            functions.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses()
            })
        data["functions"] = functions

        if output_path:
            try:
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
                return {"status": "exported", "format": "json", "output": output_path}
            except Exception as e:
                return {"error": "Failed to write file: " + str(e)}
        else:
            return data
    else:
        return {"error": "Unsupported export format: " + export_format}

# --- Command Router ---

def handle_find_string(args):
    """Find string references."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_strings(args.get("pattern", ""))
    except Exception as e:
        return {"error": "Failed to find strings: " + str(e)}

def handle_find_bytes(args):
    """Find byte patterns."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_bytes(args.get("hex", ""))
    except Exception as e:
        return {"error": "Failed to find bytes: " + str(e)}

def handle_find_function(args):
    """Find functions by pattern."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_functions(args.get("pattern", ""))
    except Exception as e:
        return {"error": "Failed to find functions: " + str(e)}

def handle_find_calls(args):
    """Find calls to function."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_calls(args.get("function", ""))
    except Exception as e:
        return {"error": "Failed to find calls: " + str(e)}

def handle_find_crypto(args):
    """Find crypto constants."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_crypto()
    except Exception as e:
        return {"error": "Failed to find crypto: " + str(e)}

def handle_find_interesting(args):
    """Find interesting functions."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import find
        return find.find_interesting()
    except Exception as e:
        return {"error": "Failed to find interesting: " + str(e)}

def handle_script_run(args):
    """Run a script file."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import script_runner
        return script_runner.run_script(args.get("path", ""), args.get("args", []))
    except Exception as e:
        return {"error": "Failed to run script: " + str(e)}

def handle_script_python(args):
    """Execute Python code."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import script_runner
        return script_runner.exec_python(args.get("code", ""))
    except Exception as e:
        return {"error": "Failed to execute Python: " + str(e)}

def handle_script_java(args):
    """Execute Java code."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import script_runner
        return script_runner.exec_java(args.get("code", ""))
    except Exception as e:
        return {"error": "Failed to execute Java: " + str(e)}

def handle_script_list(args):
    """List available scripts."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import script_runner
        return script_runner.list_scripts()
    except Exception as e:
        return {"error": "Failed to list scripts: " + str(e)}

# --- Symbol Handlers ---

def handle_symbol_list(args):
    """List symbols."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import symbols
        return symbols.list_symbols(args.get("filter"))
    except Exception as e:
        return {"error": "Failed to list symbols: " + str(e)}

def handle_symbol_get(args):
    """Get symbol details."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import symbols
        return symbols.get_symbol(args.get("name", ""))
    except Exception as e:
        return {"error": "Failed to get symbol: " + str(e)}

def handle_symbol_create(args):
    """Create a symbol."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import symbols
        return symbols.create_symbol(args.get("address", ""), args.get("name", ""))
    except Exception as e:
        return {"error": "Failed to create symbol: " + str(e)}

def handle_symbol_delete(args):
    """Delete a symbol."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import symbols
        return symbols.delete_symbol(args.get("name", ""))
    except Exception as e:
        return {"error": "Failed to delete symbol: " + str(e)}

def handle_symbol_rename(args):
    """Rename a symbol."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import symbols
        return symbols.rename_symbol(args.get("old_name", ""), args.get("new_name", ""))
    except Exception as e:
        return {"error": "Failed to rename symbol: " + str(e)}

# --- Type Handlers ---

def handle_type_list(args):
    """List data types."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import types
        return types.list_types()
    except Exception as e:
        return {"error": "Failed to list types: " + str(e)}

def handle_type_get(args):
    """Get type details."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import types
        return types.get_type(args.get("name", ""))
    except Exception as e:
        return {"error": "Failed to get type: " + str(e)}

def handle_type_create(args):
    """Create a data type."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import types
        # The Python script expects a type name; CLI passes "definition" as the name
        return types.create_type(args.get("definition", args.get("name", "")))
    except Exception as e:
        return {"error": "Failed to create type: " + str(e)}

def handle_type_apply(args):
    """Apply a type to an address."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import types
        return types.apply_type(args.get("address", ""), args.get("type_name", ""))
    except Exception as e:
        return {"error": "Failed to apply type: " + str(e)}

# --- Comment Handlers ---

def handle_comment_list(args):
    """List comments."""
    try:
        comments = import_ghidra_module("comments")
        return comments.list_comments()
    except Exception as e:
        return {"error": "Failed to list comments: " + str(e)}

def handle_comment_get(args):
    """Get comments at address."""
    try:
        comments = import_ghidra_module("comments")
        return comments.get_comments(args.get("address", ""))
    except Exception as e:
        return {"error": "Failed to get comments: " + str(e)}

def handle_comment_set(args):
    """Set a comment at address."""
    try:
        comments = import_ghidra_module("comments")
        comment_type = args.get("comment_type", "EOL") or "EOL"  # Default to EOL
        return comments.set_comment(args.get("address", ""), args.get("text", ""), comment_type)
    except Exception as e:
        return {"error": "Failed to set comment: " + str(e)}

def handle_comment_delete(args):
    """Delete comment at address."""
    try:
        comments = import_ghidra_module("comments")
        return comments.delete_comment(args.get("address", ""))
    except Exception as e:
        return {"error": "Failed to delete comment: " + str(e)}

# --- Graph Handlers ---

def handle_graph_calls(args):
    """Get call graph."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import graph
        return graph.get_call_graph(args.get("limit"))
    except Exception as e:
        return {"error": "Failed to get call graph: " + str(e)}

def handle_graph_callers(args):
    """Get callers of a function."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import graph
        return graph.get_callers(args.get("function", ""), args.get("depth", 1))
    except Exception as e:
        return {"error": "Failed to get callers: " + str(e)}

def handle_graph_callees(args):
    """Get callees of a function."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import graph
        return graph.get_callees(args.get("function", ""), args.get("depth", 1))
    except Exception as e:
        return {"error": "Failed to get callees: " + str(e)}

def handle_graph_export(args):
    """Export call graph."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import graph
        return graph.export_graph(args.get("format", "dot"))
    except Exception as e:
        return {"error": "Failed to export graph: " + str(e)}

# --- Diff Handlers ---

def handle_diff_programs(args):
    """Diff two programs."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import diff
        return diff.diff_programs(args.get("program1", ""), args.get("program2", ""))
    except Exception as e:
        return {"error": "Failed to diff programs: " + str(e)}

def handle_diff_functions(args):
    """Diff two functions."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import diff
        return diff.diff_functions(args.get("func1", ""), args.get("func2", ""))
    except Exception as e:
        return {"error": "Failed to diff functions: " + str(e)}

# --- Patch Handlers ---

def handle_patch_bytes(args):
    """Patch bytes at address."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import patch
        return patch.patch_bytes(args.get("address", ""), args.get("hex", ""))
    except Exception as e:
        return {"error": "Failed to patch bytes: " + str(e)}

def handle_patch_nop(args):
    """NOP instruction at address."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import patch
        return patch.patch_nop(args.get("address", ""))
    except Exception as e:
        return {"error": "Failed to NOP: " + str(e)}

def handle_patch_export(args):
    """Export patches."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import patch
        return patch.export_patches(args.get("output", ""))
    except Exception as e:
        return {"error": "Failed to export patches: " + str(e)}

# --- Disasm Handler ---

def handle_disasm(args):
    """Disassemble at address."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import disasm
        return disasm.disassemble(args.get("address", ""), args.get("count", 10))
    except Exception as e:
        return {"error": "Failed to disassemble: " + str(e)}

# --- Stats Handler ---

def handle_stats(args):
    """Get program statistics."""
    import sys
    import os
    script_dir = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, script_dir)
    try:
        import stats
        return stats.get_stats()
    except Exception as e:
        return {"error": "Failed to get stats: " + str(e)}

# --- Import/Analyze Handlers ---

def handle_import(args):
    """Import a binary into the current project."""
    from ghidra.app.util.importer import AutoImporter
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File

    binary_path = args.get("binary_path")
    if not binary_path:
        return {"error": "No binary_path provided"}

    program_name = args.get("program")
    if not program_name:
        binary_file = File(binary_path)
        program_name = binary_file.getName()

    project = state.getProject()
    if project is None:
        return {"error": "No project open"}

    try:
        binary_file = File(binary_path)
        if not binary_file.exists():
            return {"error": "Binary file not found: " + binary_path}

        monitor = ConsoleTaskMonitor()
        project_data = project.getProjectData()

        imported = AutoImporter.importByUsingBestGuess(
            binary_file,
            None,
            project_data.getRootFolder(),
            program_name,
            monitor
        )

        if imported is None:
            return {"error": "Failed to import binary"}

        return {"status": "success", "program": program_name}

    except Exception as e:
        return {"error": "Import failed: " + str(e)}

def handle_analyze(args):
    """Trigger auto-analysis on the current program."""
    from ghidra.app.cmd.analysis import AutoAnalysisManager
    from ghidra.util.task import ConsoleTaskMonitor

    program_name = args.get("program")
    if not program_name:
        return {"error": "No program name provided"}

    if currentProgram is None:
        return {"error": "No program currently loaded"}

    if currentProgram.getName() != program_name:
        return {"error": "Program mismatch: expected " + program_name + " but current is " + currentProgram.getName()}

    try:
        monitor = ConsoleTaskMonitor()
        auto_mgr = AutoAnalysisManager.getAnalysisManager(currentProgram)

        if auto_mgr is None:
            return {"error": "Could not get AutoAnalysisManager"}

        auto_mgr.reAnalyzeAll(None)
        auto_mgr.startAnalysis(monitor)

        return {"status": "success", "program": program_name}

    except Exception as e:
        return {"error": "Analysis failed: " + str(e)}

COMMANDS = {
    "ping": handle_ping,
    # Import/Analyze commands
    "import": handle_import,
    "analyze": handle_analyze,
    "program_info": handle_program_info,
    "program_close": handle_program_close,
    "program_delete": handle_program_delete,
    "program_export": handle_program_export,
    "list_functions": handle_list_functions,
    "decompile": handle_decompile,
    "list_strings": handle_list_strings,
    "list_imports": handle_list_imports,
    "list_exports": handle_list_exports,
    "memory_map": handle_memory_map,
    "xrefs_to": handle_xrefs_to,
    "xrefs_from": handle_xrefs_from,
    "find_string": handle_find_string,
    "find_bytes": handle_find_bytes,
    "find_function": handle_find_function,
    "find_calls": handle_find_calls,
    "find_crypto": handle_find_crypto,
    "find_interesting": handle_find_interesting,
    "script_run": handle_script_run,
    "script_python": handle_script_python,
    "script_java": handle_script_java,
    "script_list": handle_script_list,
    # Symbol commands
    "symbol_list": handle_symbol_list,
    "symbol_get": handle_symbol_get,
    "symbol_create": handle_symbol_create,
    "symbol_delete": handle_symbol_delete,
    "symbol_rename": handle_symbol_rename,
    # Type commands
    "type_list": handle_type_list,
    "type_get": handle_type_get,
    "type_create": handle_type_create,
    "type_apply": handle_type_apply,
    # Comment commands
    "comment_list": handle_comment_list,
    "comment_get": handle_comment_get,
    "comment_set": handle_comment_set,
    "comment_delete": handle_comment_delete,
    # Graph commands
    "graph_calls": handle_graph_calls,
    "graph_callers": handle_graph_callers,
    "graph_callees": handle_graph_callees,
    "graph_export": handle_graph_export,
    # Diff commands
    "diff_programs": handle_diff_programs,
    "diff_functions": handle_diff_functions,
    # Patch commands
    "patch_bytes": handle_patch_bytes,
    "patch_nop": handle_patch_nop,
    "patch_export": handle_patch_export,
    # Other commands
    "disasm": handle_disasm,
    "stats": handle_stats,
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

def is_headless_mode():
    """Check if running in headless mode (via analyzeHeadless or pyghidraRun --headless)."""
    # Check Ghidra's built-in function (available in GhidraScript context)
    try:
        # isRunningHeadless is injected by Ghidra into script namespace
        if isRunningHeadless():
            return True
    except NameError:
        pass

    # PyGhidra injects getScriptArgs() instead of args variable
    try:
        script_args = getScriptArgs()
        if script_args is not None:
            return True  # If we can get script args, we're running as a Ghidra script
    except NameError:
        pass

    # Fallback: check environment - headless mode typically has no display
    import os
    if os.environ.get('DISPLAY') is None and os.environ.get('WAYLAND_DISPLAY') is None:
        return True

    return False

if __name__ == "__main__" or True:  # Also runs when sourced by Ghidra
    # Determine port from args if provided
    port = BRIDGE_PORT
    if 'args' in dir() and len(args) > 0:
        try:
            port = int(args[0])
        except:
            pass

    # If running headless, block on server (keeps process alive)
    # Otherwise, run in background thread for GUI mode
    if is_headless_mode():
        start_server(port)
    else:
        # GUI mode - run in background thread to not freeze UI
        t = threading.Thread(target=start_server, args=(port,))
        t.daemon = True
        t.start()
        print("Bridge started in background on port " + str(port))
