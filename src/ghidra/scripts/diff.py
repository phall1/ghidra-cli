# Diff operations script
# @category CLI

import sys
import json

def diff_programs(prog1, prog2):
    """Compare two programs structurally."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        func_manager = currentProgram.getFunctionManager()
        memory = currentProgram.getMemory()
        symbol_table = currentProgram.getSymbolTable()

        prog1_stats = {
            "name": prog1,
            "function_count": func_manager.getFunctionCount(),
            "memory_size": memory.getSize(),
            "symbol_count": symbol_table.getNumSymbols()
        }

        memory_blocks = []
        for block in memory.getBlocks():
            memory_blocks.append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize()
            })

        prog1_stats["memory_blocks"] = memory_blocks

        return {
            "program1": prog1_stats,
            "program2": {"name": prog2, "note": "Comparison requires loading second program"},
            "status": "partial",
            "message": "Single program stats returned (multi-program comparison not implemented)"
        }
    except Exception as e:
        return {"error": "Failed to diff programs: " + str(e)}

def diff_functions(func1, func2):
    """Compare two functions by decompilation."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        from ghidra.app.decompiler import DecompInterface

        func_manager = currentProgram.getFunctionManager()

        target_func1 = None
        target_func2 = None

        for func in func_manager.getFunctions(True):
            if func.getName() == func1:
                target_func1 = func
            if func.getName() == func2:
                target_func2 = func

        if target_func1 is None:
            return {"error": "Function not found: " + func1}
        if target_func2 is None:
            return {"error": "Function not found: " + func2}

        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)

        result1 = decompiler.decompileFunction(target_func1, 30, monitor)
        result2 = decompiler.decompileFunction(target_func2, 30, monitor)

        if not result1.decompileCompleted():
            return {"error": "Failed to decompile " + func1}
        if not result2.decompileCompleted():
            return {"error": "Failed to decompile " + func2}

        code1 = result1.getDecompiledFunction().getC()
        code2 = result2.getDecompiledFunction().getC()

        lines1 = code1.split('\n')
        lines2 = code2.split('\n')

        diff_lines = []
        max_lines = max(len(lines1), len(lines2))

        for i in range(max_lines):
            line1 = lines1[i] if i < len(lines1) else ""
            line2 = lines2[i] if i < len(lines2) else ""

            if line1 != line2:
                diff_lines.append({
                    "line": i + 1,
                    "func1": line1,
                    "func2": line2,
                    "status": "changed"
                })

        return {
            "func1": {"name": func1, "lines": len(lines1), "code": code1},
            "func2": {"name": func2, "lines": len(lines2), "code": code2},
            "differences": diff_lines,
            "diff_count": len(diff_lines)
        }
    except Exception as e:
        return {"error": "Failed to diff functions: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "diff_programs":
            result = diff_programs(args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "")
        elif command == "diff_functions":
            result = diff_functions(args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "")
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
