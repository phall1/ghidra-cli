# Symbol operations script
# @category CLI

import sys
import json

def list_symbols(name_filter):
    """List all symbols in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    symbol_table = currentProgram.getSymbolTable()
    symbols = []

    for symbol in symbol_table.getAllSymbols(True):
        name = symbol.getName()

        if name_filter and name_filter.lower() not in name.lower():
            continue

        symbol_data = {
            "name": name,
            "address": str(symbol.getAddress()),
            "type": str(symbol.getSymbolType()),
            "source": str(symbol.getSource()),
            "is_primary": symbol.isPrimary()
        }
        symbols.append(symbol_data)

    return {"symbols": symbols, "count": len(symbols)}

def get_symbol(address_or_name):
    """Get symbol at specific address or by name."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    symbol_table = currentProgram.getSymbolTable()

    if address_or_name.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in address_or_name):
        try:
            addr = currentProgram.getAddressFactory().getAddress(address_or_name)
            if addr is None:
                return {"error": "Invalid address: " + address_or_name}

            symbols_at_addr = symbol_table.getSymbols(addr)
            if not symbols_at_addr:
                return {"error": "No symbol at address: " + address_or_name}

            result_symbols = []
            for symbol in symbols_at_addr:
                result_symbols.append({
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType()),
                    "source": str(symbol.getSource())
                })
            return {"symbols": result_symbols}
        except Exception as e:
            return {"error": "Failed to get symbol: " + str(e)}
    else:
        symbols = symbol_table.getSymbols(address_or_name)
        if not symbols or len(symbols) == 0:
            return {"error": "Symbol not found: " + address_or_name}

        result_symbols = []
        for symbol in symbols:
            result_symbols.append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource())
            })
        return {"symbols": result_symbols}

def create_symbol(address_str, name):
    """Create a new symbol."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        symbol_table = currentProgram.getSymbolTable()
        from ghidra.program.model.symbol import SourceType

        symbol_table.createLabel(addr, name, SourceType.USER_DEFINED)

        return {"status": "created", "address": address_str, "name": name}
    except Exception as e:
        return {"error": "Failed to create symbol: " + str(e)}

def delete_symbol(name):
    """Delete a symbol by name."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getSymbols(name)

        if not symbols or len(symbols) == 0:
            return {"error": "Symbol not found: " + name}

        for symbol in symbols:
            symbol.delete()

        return {"status": "deleted", "name": name}
    except Exception as e:
        return {"error": "Failed to delete symbol: " + str(e)}

def rename_symbol(old_name, new_name):
    """Rename a symbol."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        symbol_table = currentProgram.getSymbolTable()
        symbols = symbol_table.getSymbols(old_name)

        if not symbols or len(symbols) == 0:
            return {"error": "Symbol not found: " + old_name}

        for symbol in symbols:
            symbol.setName(new_name, symbol.getSource())

        return {"status": "renamed", "old_name": old_name, "new_name": new_name}
    except Exception as e:
        return {"error": "Failed to rename symbol: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "list":
            result = list_symbols(args[1] if len(args) > 1 else None)
        elif command == "get":
            result = get_symbol(args[1] if len(args) > 1 else None)
        elif command == "create":
            result = create_symbol(args[1] if len(args) > 1 else None, args[2] if len(args) > 2 else None)
        elif command == "delete":
            result = delete_symbol(args[1] if len(args) > 1 else None)
        elif command == "rename":
            result = rename_symbol(args[1] if len(args) > 1 else None, args[2] if len(args) > 2 else None)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
