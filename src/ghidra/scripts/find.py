# Find/search operations script
# @category CLI

import sys
import json

def find_strings(pattern):
    """Find string references matching pattern."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        listing = currentProgram.getListing()
        results = []

        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            if data.hasStringValue():
                string_val = str(data.getValue())
                if pattern.lower() in string_val.lower():
                    results.append({
                        "address": str(data.getAddress()),
                        "value": string_val,
                        "length": data.getLength()
                    })

        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": "Failed to find strings: " + str(e)}

def find_bytes(hex_pattern):
    """Find byte patterns in memory."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        hex_clean = hex_pattern.replace("0x", "").replace(" ", "")

        byte_array = []
        for i in range(0, len(hex_clean), 2):
            byte_val = int(hex_clean[i:i+2], 16)
            if byte_val > 127:
                byte_val = byte_val - 256
            byte_array.append(byte_val)

        from java.lang import Byte
        search_bytes = [Byte(b) for b in byte_array]

        memory = currentProgram.getMemory()
        results = []

        addr = memory.getMinAddress()
        while addr is not None:
            found_addr = memory.findBytes(addr, search_bytes, None, True, monitor)
            if found_addr is None:
                break
            results.append({"address": str(found_addr)})
            addr = found_addr.add(1)
            if len(results) >= 100:
                break

        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": "Failed to find bytes: " + str(e)}

def find_functions(pattern):
    """Find functions matching name pattern."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        func_manager = currentProgram.getFunctionManager()
        results = []

        for func in func_manager.getFunctions(True):
            func_name = func.getName()

            if "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(func_name, pattern):
                    results.append({
                        "name": func_name,
                        "address": str(func.getEntryPoint()),
                        "size": func.getBody().getNumAddresses()
                    })
            elif pattern.lower() in func_name.lower():
                results.append({
                    "name": func_name,
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses()
                })

        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": "Failed to find functions: " + str(e)}

def find_calls(func_name):
    """Find all calls to a specific function."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        func_manager = currentProgram.getFunctionManager()
        target_func = None

        for func in func_manager.getFunctions(True):
            if func.getName() == func_name:
                target_func = func
                break

        if target_func is None:
            return {"error": "Function not found: " + func_name}

        ref_manager = currentProgram.getReferenceManager()
        target_addr = target_func.getEntryPoint()
        refs = ref_manager.getReferencesTo(target_addr)

        results = []
        for ref in refs:
            if ref.getReferenceType().isCall():
                from_addr = ref.getFromAddress()
                from_func = func_manager.getFunctionContaining(from_addr)

                caller_name = "unknown"
                if from_func is not None:
                    caller_name = from_func.getName()

                results.append({
                    "address": str(from_addr),
                    "caller": caller_name,
                    "type": str(ref.getReferenceType())
                })

        return {"results": results, "count": len(results), "target": func_name}
    except Exception as e:
        return {"error": "Failed to find calls: " + str(e)}

def find_crypto():
    """Find potential crypto constants."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        memory = currentProgram.getMemory()
        results = []

        crypto_patterns = {
            "AES S-box": "637c777bf26b6fc53001672bfed7ab76",
            "SHA-256": "428a2f98d728ae227137449123ef65cd",
            "MD5": "d76aa478e8c7b756242070db01234567",
        }

        for name, pattern in crypto_patterns.items():
            hex_clean = pattern.replace(" ", "")
            byte_array = []

            for i in range(0, len(hex_clean), 2):
                byte_val = int(hex_clean[i:i+2], 16)
                if byte_val > 127:
                    byte_val = byte_val - 256
                byte_array.append(byte_val)

            from java.lang import Byte
            search_bytes = [Byte(b) for b in byte_array]

            addr = memory.getMinAddress()
            found_addr = memory.findBytes(addr, search_bytes, None, True, monitor)

            if found_addr is not None:
                results.append({
                    "type": name,
                    "address": str(found_addr),
                    "pattern": pattern
                })

        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": "Failed to find crypto: " + str(e)}

def find_interesting():
    """Find interesting functions using heuristics."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        func_manager = currentProgram.getFunctionManager()
        ref_manager = currentProgram.getReferenceManager()
        results = []

        suspicious_names = ["password", "key", "encrypt", "decrypt", "crypt", "auth", "login", "admin", "secret"]

        for func in func_manager.getFunctions(True):
            func_name = func.getName()
            func_addr = func.getEntryPoint()
            func_size = func.getBody().getNumAddresses()

            xref_count = len(list(ref_manager.getReferencesTo(func_addr)))

            reasons = []

            if func_size > 1000:
                reasons.append("large function ({} bytes)".format(func_size))

            if xref_count > 50:
                reasons.append("many xrefs ({})".format(xref_count))

            for sus_name in suspicious_names:
                if sus_name in func_name.lower():
                    reasons.append("suspicious name")
                    break

            if reasons:
                results.append({
                    "name": func_name,
                    "address": str(func_addr),
                    "size": func_size,
                    "xrefs": xref_count,
                    "reasons": reasons
                })

        results.sort(key=lambda x: len(x["reasons"]), reverse=True)

        return {"results": results[:50], "count": len(results)}
    except Exception as e:
        return {"error": "Failed to find interesting functions: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "find_string":
            result = find_strings(args[1] if len(args) > 1 else "")
        elif command == "find_bytes":
            result = find_bytes(args[1] if len(args) > 1 else "")
        elif command == "find_function":
            result = find_functions(args[1] if len(args) > 1 else "")
        elif command == "find_calls":
            result = find_calls(args[1] if len(args) > 1 else "")
        elif command == "find_crypto":
            result = find_crypto()
        elif command == "find_interesting":
            result = find_interesting()
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
