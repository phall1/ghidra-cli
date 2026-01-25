# Patch operations script
# @category CLI

import sys
import json

def patch_bytes(address_str, hex_data):
    """Patch bytes at the specified address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        hex_clean = hex_data.replace("0x", "").replace(" ", "")

        byte_array = []
        for i in range(0, len(hex_clean), 2):
            byte_val = int(hex_clean[i:i+2], 16)
            if byte_val > 127:
                byte_val = byte_val - 256
            byte_array.append(byte_val)

        from java.lang import Byte
        patch_bytes = [Byte(b) for b in byte_array]

        memory = currentProgram.getMemory()
        memory.setBytes(addr, patch_bytes)

        return {
            "status": "patched",
            "address": str(addr),
            "bytes": len(patch_bytes)
        }
    except Exception as e:
        return {"error": "Failed to patch bytes: " + str(e)}

def patch_nop(address_str):
    """NOP out instruction at the specified address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        listing = currentProgram.getListing()
        instruction = listing.getInstructionAt(addr)

        if instruction is None:
            return {"error": "No instruction at address: " + address_str}

        instr_length = instruction.getLength()

        processor = currentProgram.getLanguage().getProcessor().toString()

        if "x86" in processor.lower():
            nop_byte = 0x90
        elif "ARM" in processor or "aarch" in processor.lower():
            nop_byte = 0x00
        else:
            nop_byte = 0x00

        from java.lang import Byte
        nop_bytes = [Byte(nop_byte) for _ in range(instr_length)]

        memory = currentProgram.getMemory()
        memory.setBytes(addr, nop_bytes)

        return {
            "status": "nopped",
            "address": str(addr),
            "bytes": instr_length
        }
    except Exception as e:
        return {"error": "Failed to NOP instruction: " + str(e)}

def export_binary(output_path):
    """Export the patched binary."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        from ghidra.app.util.exporter import BinaryExporter
        from java.io import File

        exporter = BinaryExporter()
        output_file = File(output_path)

        exporter.export(output_file, currentProgram, None, monitor)

        return {
            "status": "exported",
            "output": output_path
        }
    except Exception as e:
        return {"error": "Failed to export binary: " + str(e)}

# Alias for bridge.py compatibility
def export_patches(output_path):
    """Export patches (alias for export_binary)."""
    return export_binary(output_path)

if __name__ == "__main__":
    try:
        args = getScriptArgs()

        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "patch_bytes":
            result = patch_bytes(args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "")
        elif command == "patch_nop":
            result = patch_nop(args[1] if len(args) > 1 else "")
        elif command == "patch_export":
            result = export_binary(args[1] if len(args) > 1 else "")
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
