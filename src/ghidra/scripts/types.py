# Type operations script
# @category CLI

import sys
import json

def list_types():
    """List all defined types in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    data_type_manager = currentProgram.getDataTypeManager()
    types = []

    for data_type in data_type_manager.getAllDataTypes():
        type_data = {
            "name": data_type.getName(),
            "path": data_type.getPathName(),
            "category": data_type.getCategoryPath().toString(),
            "size": data_type.getLength()
        }
        types.append(type_data)

    return {"types": types, "count": len(types)}

def get_type(type_name):
    """Get type definition by name."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    data_type_manager = currentProgram.getDataTypeManager()

    data_type = data_type_manager.getDataType(type_name)
    if data_type is None:
        for dt in data_type_manager.getAllDataTypes():
            if dt.getName() == type_name:
                data_type = dt
                break

    if data_type is None:
        return {"error": "Type not found: " + type_name}

    type_info = {
        "name": data_type.getName(),
        "path": data_type.getPathName(),
        "category": data_type.getCategoryPath().toString(),
        "size": data_type.getLength(),
        "description": data_type.getDescription()
    }

    from ghidra.program.model.data import Structure, Union
    if isinstance(data_type, Structure) or isinstance(data_type, Union):
        components = []
        for component in data_type.getComponents():
            components.append({
                "name": component.getFieldName(),
                "type": component.getDataType().getName(),
                "offset": component.getOffset(),
                "size": component.getLength()
            })
        type_info["components"] = components

    return type_info

def create_type(type_name):
    """Create a new empty struct type."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        from ghidra.program.model.data import StructureDataType
        data_type_manager = currentProgram.getDataTypeManager()

        new_struct = StructureDataType(type_name, 0)
        data_type_manager.addDataType(new_struct, None)

        return {"status": "created", "name": type_name}
    except Exception as e:
        return {"error": "Failed to create type: " + str(e)}

def apply_type(address_str, type_name):
    """Apply a type to a specific address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        data_type_manager = currentProgram.getDataTypeManager()
        data_type = data_type_manager.getDataType(type_name)

        if data_type is None:
            for dt in data_type_manager.getAllDataTypes():
                if dt.getName() == type_name:
                    data_type = dt
                    break

        if data_type is None:
            return {"error": "Type not found: " + type_name}

        listing = currentProgram.getListing()
        listing.createData(addr, data_type)

        return {"status": "applied", "address": address_str, "type": type_name}
    except Exception as e:
        return {"error": "Failed to apply type: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "list":
            result = list_types()
        elif command == "get":
            result = get_type(args[1] if len(args) > 1 else None)
        elif command == "create":
            result = create_type(args[1] if len(args) > 1 else None)
        elif command == "apply":
            result = apply_type(args[1] if len(args) > 1 else None, args[2] if len(args) > 2 else None)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
