# Program statistics script
# @category CLI

import sys
import json

def get_stats():
    """Gather comprehensive program statistics."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        func_manager = currentProgram.getFunctionManager()
        symbol_table = currentProgram.getSymbolTable()
        memory = currentProgram.getMemory()
        data_type_manager = currentProgram.getDataTypeManager()
        listing = currentProgram.getListing()

        function_count = func_manager.getFunctionCount()

        symbol_count = 0
        symbol_iter = symbol_table.getAllSymbols(True)
        while symbol_iter.hasNext():
            symbol_iter.next()
            symbol_count += 1

        string_count = 0
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            if data.hasStringValue():
                string_count += 1

        memory_size = 0
        for block in memory.getBlocks():
            memory_size += block.getSize()

        section_count = len(list(memory.getBlocks()))

        import_count = 0
        export_count = 0
        for symbol in symbol_table.getExternalSymbols():
            import_count += 1

        export_iter = symbol_table.getExternalEntryPointIterator()
        while export_iter.hasNext():
            export_iter.next()
            export_count += 1

        data_type_count = data_type_manager.getDataTypeCount(False)

        instruction_count = 0
        code_unit_iter = listing.getInstructions(True)
        while code_unit_iter.hasNext():
            code_unit_iter.next()
            instruction_count += 1

        stats = {
            "functions": function_count,
            "symbols": symbol_count,
            "strings": string_count,
            "imports": import_count,
            "exports": export_count,
            "memory_size": memory_size,
            "sections": section_count,
            "data_types": data_type_count,
            "instructions": instruction_count,
            "program_name": currentProgram.getName(),
            "executable_format": currentProgram.getExecutableFormat(),
            "compiler": str(currentProgram.getCompiler()) if currentProgram.getCompiler() else "Unknown"
        }

        return {"stats": stats}
    except Exception as e:
        return {"error": "Failed to gather statistics: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "stats":
            result = get_stats()
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
