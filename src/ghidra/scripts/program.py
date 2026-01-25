# Program operations script
# @category CLI

import sys
import json

def close_program():
    """Close the current program."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    program_name = currentProgram.getName()
    state.getTool().closeProgram(currentProgram, False)

    return {"status": "closed", "program": program_name}

def delete_program(program_name):
    """Delete a program from the project."""
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

def get_program_info():
    """Get current program metadata."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    info = {
        "name": currentProgram.getName(),
        "path": currentProgram.getExecutablePath(),
        "format": currentProgram.getExecutableFormat(),
        "processor": str(currentProgram.getLanguage().getProcessor()),
        "language": str(currentProgram.getLanguage()),
        "compiler": currentProgram.getCompiler() if currentProgram.getCompiler() else None,
        "image_base": str(currentProgram.getImageBase()),
        "min_address": str(currentProgram.getMinAddress()),
        "max_address": str(currentProgram.getMaxAddress()),
        "creation_date": str(currentProgram.getCreationDate())
    }

    return info

def export_program(export_format, output_path):
    """Export program to specified format."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    from ghidra.app.util.exporter import Exporter
    from ghidra.framework.model import DomainFile
    from java.io import File

    if export_format == "json":
        data = get_program_info()

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
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            return {"status": "exported", "format": "json", "output": output_path}
        else:
            return data
    else:
        return {"error": "Unsupported export format: " + export_format}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "close":
            result = close_program()
        elif command == "delete":
            result = delete_program(args[1] if len(args) > 1 else None)
        elif command == "info":
            result = get_program_info()
        elif command == "export":
            fmt = args[1] if len(args) > 1 else "json"
            output = args[2] if len(args) > 2 else None
            result = export_program(fmt, output)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
