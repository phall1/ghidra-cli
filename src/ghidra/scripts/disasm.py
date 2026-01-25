# Disassembly script
# @category CLI

import sys
import json

def disassemble(address_str, count):
    """Disassemble instructions starting at address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr_factory = currentProgram.getAddressFactory()

        if address_str.startswith("0x") or address_str.startswith("0X"):
            address_str = address_str[2:]

        addr = addr_factory.getAddress(address_str)

        if addr is None:
            return {"error": "Invalid address: " + address_str}

        listing = currentProgram.getListing()
        instruction = listing.getInstructionAt(addr)

        if instruction is None:
            return {"error": "No instruction at address: " + address_str}

        results = []
        current_instr = instruction

        for i in range(count):
            if current_instr is None:
                break

            instr_addr = current_instr.getAddress()

            byte_array = current_instr.getBytes()
            bytes_hex = ""
            for b in byte_array:
                bytes_hex += "{:02x}".format(b & 0xff)

            mnemonic = current_instr.getMnemonicString()

            operands = []
            num_operands = current_instr.getNumOperands()
            for j in range(num_operands):
                operands.append(str(current_instr.getDefaultOperandRepresentation(j)))

            results.append({
                "address": str(instr_addr),
                "bytes": bytes_hex,
                "mnemonic": mnemonic,
                "operands": operands
            })

            current_instr = current_instr.getNext()

        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": "Failed to disassemble: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "disasm":
            address = args[1] if len(args) > 1 else "0x0"
            count = int(args[2]) if len(args) > 2 else 10
            result = disassemble(address, count)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
