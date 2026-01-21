/// Built-in Ghidra scripts for data extraction
/// These are Python scripts that will be written to disk and executed by Ghidra headless

pub fn get_list_functions_script() -> &'static str {
    r#"
# List all functions in the program
# @category Analysis
# @runtime Jython

import json

functions = []
function_manager = currentProgram.getFunctionManager()

for func in function_manager.getFunctions(True):
    entry = func.getEntryPoint()
    body = func.getBody()

    func_data = {
        "name": func.getName(),
        "address": entry.toString(),
        "size": body.getNumAddresses(),
        "entry_point": entry.toString(),
        "signature": func.getPrototypeString(False, False) if func.getSignature() else None,
        "calling_convention": func.getCallingConventionName(),
        "comment": func.getComment()
    }

    # Get called functions
    called = []
    refs = func.getBody().getAddresses(True)
    for addr in refs:
        for ref in currentProgram.getReferenceManager().getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                to_addr = ref.getToAddress()
                to_func = function_manager.getFunctionAt(to_addr)
                if to_func:
                    called.append(to_func.getName())

    func_data["calls"] = list(set(called))

    # Get callers
    callers = []
    refs_to = currentProgram.getReferenceManager().getReferencesTo(entry)
    for ref in refs_to:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            from_func = function_manager.getFunctionContaining(from_addr)
            if from_func:
                callers.append(from_func.getName())

    func_data["called_by"] = list(set(callers))

    functions.append(func_data)

print("---GHIDRA_CLI_START---")
print(json.dumps(functions, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_decompile_function_script() -> &'static str {
    r#"
# Decompile a specific function
# @category Analysis
# @runtime Jython

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Get function address from args
if len(args) < 1:
    print(json.dumps({"error": "No address provided"}))
    exit(1)

addr_str = args[0]
addr = currentProgram.getAddressFactory().getAddress(addr_str)

function_manager = currentProgram.getFunctionManager()
func = function_manager.getFunctionContaining(addr)

if not func:
    print(json.dumps({"error": "No function at address " + addr_str}))
    exit(1)

# Decompile
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

monitor = ConsoleTaskMonitor()
results = decompiler.decompileFunction(func, 30, monitor)

if results.decompileCompleted():
    code = results.getDecompiledFunction().getC()

    result = {
        "name": func.getName(),
        "address": func.getEntryPoint().toString(),
        "signature": func.getPrototypeString(False, False),
        "code": code
    }

    print("---GHIDRA_CLI_START---")
    print(json.dumps(result, indent=2))
    print("---GHIDRA_CLI_END---")
else:
    print("---GHIDRA_CLI_START---")
    print(json.dumps({"error": "Decompilation failed"}))
    print("---GHIDRA_CLI_END---")
"#
}

pub fn get_list_strings_script() -> &'static str {
    r#"
# List all strings in the program
# @category Analysis
# @runtime Jython

import json

strings = []
listing = currentProgram.getListing()
data_iterator = listing.getDefinedData(True)

while data_iterator.hasNext():
    data = data_iterator.next()
    if data.hasStringValue():
        try:
            # Get string value, handle Unicode properly
            string_val = unicode(data.getValue())
            string_data = {
                "address": str(data.getAddress()),
                "value": string_val,
                "length": len(string_val),
                "encoding": "unicode"
            }

            # Get references to this string
            refs = []
            refs_to = currentProgram.getReferenceManager().getReferencesTo(data.getAddress())
            for ref in refs_to:
                refs.append(str(ref.getFromAddress()))

            string_data["references"] = refs
            strings.append(string_data)
        except Exception as e:
            # Skip strings that cause encoding issues
            pass

print("---GHIDRA_CLI_START---")
print(json.dumps(strings, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_list_imports_script() -> &'static str {
    r#"
# List all imports in the program
# @category Analysis
# @runtime Jython

import json

imports = []
symbol_table = currentProgram.getSymbolTable()
external_manager = currentProgram.getExternalManager()

for symbol in symbol_table.getExternalSymbols():
    external_location = external_manager.getExternalLocation(symbol)

    if external_location:
        import_data = {
            "name": symbol.getName(),
            "address": symbol.getAddress().toString(),
            "library": external_location.getLibraryName(),
            "is_external": True
        }
        imports.append(import_data)

print("---GHIDRA_CLI_START---")
print(json.dumps(imports, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_list_exports_script() -> &'static str {
    r#"
# List all exports in the program
# @category Analysis
# @runtime Jython

import json

exports = []
symbol_table = currentProgram.getSymbolTable()

for symbol in symbol_table.getSymbolIterator():
    if symbol.isExternalEntryPoint():
        export_data = {
            "name": symbol.getName(),
            "address": symbol.getAddress().toString()
        }
        exports.append(export_data)

print("---GHIDRA_CLI_START---")
print(json.dumps(exports, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_memory_map_script() -> &'static str {
    r#"
# Get memory map
# @category Analysis
# @runtime Jython

import json

blocks = []
memory = currentProgram.getMemory()

for block in memory.getBlocks():
    block_data = {
        "name": block.getName(),
        "start": block.getStart().toString(),
        "end": block.getEnd().toString(),
        "size": block.getSize(),
        "permissions": "",
        "is_initialized": block.isInitialized(),
        "is_loaded": block.isLoaded()
    }

    # Build permissions string
    perms = ""
    if block.isRead():
        perms += "r"
    if block.isWrite():
        perms += "w"
    if block.isExecute():
        perms += "x"

    block_data["permissions"] = perms
    blocks.append(block_data)

print("---GHIDRA_CLI_START---")
print(json.dumps(blocks, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_program_info_script() -> &'static str {
    r#"
# Get program information
# @category Analysis
# @runtime Jython

import json

info = {
    "name": currentProgram.getName(),
    "executable_path": currentProgram.getExecutablePath(),
    "executable_format": currentProgram.getExecutableFormat(),
    "compiler": currentProgram.getCompiler() if currentProgram.getCompiler() else None,
    "language": currentProgram.getLanguage().toString(),
    "image_base": currentProgram.getImageBase().toString(),
    "min_address": currentProgram.getMinAddress().toString(),
    "max_address": currentProgram.getMaxAddress().toString()
}

# Count functions and instructions
function_manager = currentProgram.getFunctionManager()
info["function_count"] = function_manager.getFunctionCount()

instruction_count = 0
listing = currentProgram.getListing()
for instruction in listing.getInstructions(True):
    instruction_count += 1

info["instruction_count"] = instruction_count

print("---GHIDRA_CLI_START---")
print(json.dumps(info, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

pub fn get_xrefs_to_script() -> &'static str {
    r#"
# Get cross-references to an address
# @category Analysis
# @runtime Jython

import json

if len(args) < 1:
    print(json.dumps({"error": "No address provided"}))
    exit(1)

addr_str = args[0]
addr = currentProgram.getAddressFactory().getAddress(addr_str)

xrefs = []
refs = currentProgram.getReferenceManager().getReferencesTo(addr)
function_manager = currentProgram.getFunctionManager()

for ref in refs:
    from_addr = ref.getFromAddress()
    from_func = function_manager.getFunctionContaining(from_addr)
    to_func = function_manager.getFunctionContaining(addr)

    xref_data = {
        "from": from_addr.toString(),
        "to": addr.toString(),
        "ref_type": ref.getReferenceType().toString(),
        "from_function": from_func.getName() if from_func else None,
        "to_function": to_func.getName() if to_func else None
    }
    xrefs.append(xref_data)

print("---GHIDRA_CLI_START---")
print(json.dumps(xrefs, indent=2))
print("---GHIDRA_CLI_END---")
"#
}

/// Save a script to disk
pub fn save_script(name: &str, content: &str, scripts_dir: &std::path::Path) -> crate::error::Result<std::path::PathBuf> {
    // All scripts are Python now with PyGhidra support
    let script_path = scripts_dir.join(format!("{}.py", name));
    std::fs::write(&script_path, content)?;
    Ok(script_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scripts_not_empty() {
        assert!(!get_list_functions_script().is_empty());
        assert!(!get_decompile_function_script().is_empty());
        assert!(!get_list_strings_script().is_empty());
    }
}
