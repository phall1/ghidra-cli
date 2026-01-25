# Script execution operations
# @category CLI

import sys
import json
import os

def run_script(script_path, script_args):
    """Run a user script file."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        if not os.path.exists(script_path):
            return {"error": "Script not found: " + script_path}

        from ghidra.app.script import GhidraScriptUtil

        script_info = GhidraScriptUtil.findScriptByName(os.path.basename(script_path))
        if script_info is None:
            return {"error": "Could not load script: " + script_path}

        result = runScript(script_path, script_args if script_args else [])

        return {
            "status": "executed",
            "script": script_path,
            "result": str(result) if result is not None else None
        }
    except Exception as e:
        return {"error": "Failed to run script: " + str(e)}

def exec_python(code):
    """Execute inline Python code."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        local_vars = {
            "currentProgram": currentProgram,
            "currentAddress": currentAddress if 'currentAddress' in dir() else None,
            "currentLocation": currentLocation if 'currentLocation' in dir() else None,
            "state": state if 'state' in dir() else None
        }

        exec(code, globals(), local_vars)

        output = local_vars.get("output", None)

        return {
            "status": "executed",
            "output": str(output) if output is not None else "Code executed successfully"
        }
    except Exception as e:
        return {"error": "Failed to execute Python code: " + str(e)}

def exec_java(code):
    """Execute inline Java code."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        return {"error": "Java execution not yet implemented"}
    except Exception as e:
        return {"error": "Failed to execute Java code: " + str(e)}

def list_scripts():
    """List available scripts."""
    try:
        from ghidra.app.script import GhidraScriptUtil

        script_infos = GhidraScriptUtil.getScriptSourceDirectories()
        scripts = []

        for script_dir in script_infos:
            script_path = str(script_dir)
            if os.path.exists(script_path) and os.path.isdir(script_path):
                for filename in os.listdir(script_path):
                    if filename.endswith('.py') or filename.endswith('.java'):
                        scripts.append({
                            "name": filename,
                            "path": os.path.join(script_path, filename),
                            "type": "python" if filename.endswith('.py') else "java"
                        })

        return {"scripts": scripts, "count": len(scripts)}
    except Exception as e:
        return {"error": "Failed to list scripts: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "run":
            script_path = args[1] if len(args) > 1 else None
            script_args = args[2:] if len(args) > 2 else []
            result = run_script(script_path, script_args)
        elif command == "python":
            code = args[1] if len(args) > 1 else None
            result = exec_python(code)
        elif command == "java":
            code = args[1] if len(args) > 1 else None
            result = exec_java(code)
        elif command == "list":
            result = list_scripts()
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
