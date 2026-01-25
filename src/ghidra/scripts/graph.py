# Graph operations script
# @category CLI

import sys
import json

def get_call_graph(limit):
    """Build full call graph."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    function_manager = currentProgram.getFunctionManager()
    reference_manager = currentProgram.getReferenceManager()

    nodes = []
    edges = []
    count = 0

    for func in function_manager.getFunctions(True):
        if limit and count >= limit:
            break

        func_addr = str(func.getEntryPoint())
        nodes.append({
            "id": func_addr,
            "name": func.getName(),
            "address": func_addr
        })

        from ghidra.program.model.symbol import RefType
        refs = reference_manager.getReferencesFrom(func.getEntryPoint())
        for ref in refs:
            if ref.getReferenceType().isCall():
                target_addr = ref.getToAddress()
                target_func = function_manager.getFunctionAt(target_addr)
                if target_func:
                    edges.append({
                        "from": func_addr,
                        "to": str(target_addr),
                        "type": "call"
                    })

        count += 1

    return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

def get_callers(function_name, depth):
    """Get functions that call the specified function."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    function_manager = currentProgram.getFunctionManager()
    reference_manager = currentProgram.getReferenceManager()

    target_func = None
    if function_name.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in function_name):
        addr = currentProgram.getAddressFactory().getAddress(function_name)
        if addr:
            target_func = function_manager.getFunctionAt(addr)
    else:
        for func in function_manager.getFunctions(True):
            if func.getName() == function_name:
                target_func = func
                break

    if not target_func:
        return {"error": "Function not found: " + function_name}

    callers = []
    visited = set()

    def find_callers(func, current_depth):
        if depth and current_depth >= depth:
            return
        if str(func.getEntryPoint()) in visited:
            return

        visited.add(str(func.getEntryPoint()))

        from ghidra.program.model.symbol import RefType
        refs = reference_manager.getReferencesTo(func.getEntryPoint())

        for ref in refs:
            if ref.getReferenceType().isCall():
                from_addr = ref.getFromAddress()
                caller_func = function_manager.getFunctionContaining(from_addr)
                if caller_func:
                    caller_info = {
                        "name": caller_func.getName(),
                        "address": str(caller_func.getEntryPoint()),
                        "call_site": str(from_addr),
                        "depth": current_depth
                    }
                    callers.append(caller_info)

                    if depth is None or current_depth + 1 < depth:
                        find_callers(caller_func, current_depth + 1)

    find_callers(target_func, 0)

    return {"function": function_name, "callers": callers, "count": len(callers)}

def get_callees(function_name, depth):
    """Get functions called by the specified function."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    function_manager = currentProgram.getFunctionManager()
    reference_manager = currentProgram.getReferenceManager()

    target_func = None
    if function_name.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in function_name):
        addr = currentProgram.getAddressFactory().getAddress(function_name)
        if addr:
            target_func = function_manager.getFunctionAt(addr)
    else:
        for func in function_manager.getFunctions(True):
            if func.getName() == function_name:
                target_func = func
                break

    if not target_func:
        return {"error": "Function not found: " + function_name}

    callees = []
    visited = set()

    def find_callees(func, current_depth):
        if depth and current_depth >= depth:
            return
        if str(func.getEntryPoint()) in visited:
            return

        visited.add(str(func.getEntryPoint()))

        from ghidra.program.model.symbol import RefType
        refs = reference_manager.getReferencesFrom(func.getEntryPoint())

        for ref in refs:
            if ref.getReferenceType().isCall():
                to_addr = ref.getToAddress()
                callee_func = function_manager.getFunctionAt(to_addr)
                if callee_func:
                    callee_info = {
                        "name": callee_func.getName(),
                        "address": str(callee_func.getEntryPoint()),
                        "call_site": str(ref.getFromAddress()),
                        "depth": current_depth
                    }
                    callees.append(callee_info)

                    if depth is None or current_depth + 1 < depth:
                        find_callees(callee_func, current_depth + 1)

    find_callees(target_func, 0)

    return {"function": function_name, "callees": callees, "count": len(callees)}

def export_graph(export_format):
    """Export call graph in specified format."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    graph_data = get_call_graph(None)
    if "error" in graph_data:
        return graph_data

    if export_format == "json":
        return graph_data
    elif export_format == "dot":
        lines = ["digraph CallGraph {"]
        lines.append('  rankdir=LR;')
        lines.append('  node [shape=box];')

        for node in graph_data["nodes"]:
            node_id = node["id"].replace(":", "_")
            label = node["name"]
            lines.append('  "{}" [label="{}"];'.format(node_id, label))

        for edge in graph_data["edges"]:
            from_id = edge["from"].replace(":", "_")
            to_id = edge["to"].replace(":", "_")
            lines.append('  "{}" -> "{}";'.format(from_id, to_id))

        lines.append("}")
        return {"format": "dot", "output": "\n".join(lines)}
    else:
        return {"error": "Unsupported format: " + export_format}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "calls":
            limit = int(args[1]) if len(args) > 1 and args[1] else None
            result = get_call_graph(limit)
        elif command == "callers":
            func_name = args[1] if len(args) > 1 else None
            depth = int(args[2]) if len(args) > 2 and args[2] else None
            result = get_callers(func_name, depth)
        elif command == "callees":
            func_name = args[1] if len(args) > 1 else None
            depth = int(args[2]) if len(args) > 2 and args[2] else None
            result = get_callees(func_name, depth)
        elif command == "export":
            fmt = args[1] if len(args) > 1 else "json"
            result = export_graph(fmt)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
