# Comment operations script
# @category CLI

import sys
import json

def list_comments():
    """List all comments in the program."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    listing = currentProgram.getListing()
    comments = []

    code_unit_iter = listing.getCommentAddressIterator(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), True)

    for addr in code_unit_iter:
        code_unit = listing.getCodeUnitAt(addr)
        if code_unit is None:
            continue

        from ghidra.program.model.listing import CodeUnit

        comment_types = [
            ("EOL", CodeUnit.EOL_COMMENT),
            ("PRE", CodeUnit.PRE_COMMENT),
            ("POST", CodeUnit.POST_COMMENT),
            ("PLATE", CodeUnit.PLATE_COMMENT)
        ]

        for comment_name, comment_type in comment_types:
            text = code_unit.getComment(comment_type)
            if text:
                comments.append({
                    "address": str(addr),
                    "type": comment_name,
                    "text": text
                })

    return {"comments": comments, "count": len(comments)}

def get_comments(address_str):
    """Get comments at a specific address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        listing = currentProgram.getListing()
        code_unit = listing.getCodeUnitAt(addr)

        if code_unit is None:
            return {"error": "No code unit at address: " + address_str}

        from ghidra.program.model.listing import CodeUnit

        comments = []
        comment_types = [
            ("EOL", CodeUnit.EOL_COMMENT),
            ("PRE", CodeUnit.PRE_COMMENT),
            ("POST", CodeUnit.POST_COMMENT),
            ("PLATE", CodeUnit.PLATE_COMMENT)
        ]

        for comment_name, comment_type in comment_types:
            text = code_unit.getComment(comment_type)
            if text:
                comments.append({
                    "type": comment_name,
                    "text": text
                })

        return {"address": address_str, "comments": comments}
    except Exception as e:
        return {"error": "Failed to get comments: " + str(e)}

def set_comment(address_str, text, comment_type_str):
    """Set a comment at a specific address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        listing = currentProgram.getListing()
        from ghidra.program.model.listing import CodeUnit

        valid_types = {"EOL", "PRE", "POST", "PLATE"}
        if comment_type_str not in valid_types:
            return {"error": "Invalid comment type: " + comment_type_str + ". Must be one of: EOL, PRE, POST, PLATE"}

        comment_type = CodeUnit.EOL_COMMENT
        if comment_type_str == "PRE":
            comment_type = CodeUnit.PRE_COMMENT
        elif comment_type_str == "POST":
            comment_type = CodeUnit.POST_COMMENT
        elif comment_type_str == "PLATE":
            comment_type = CodeUnit.PLATE_COMMENT

        listing.setComment(addr, comment_type, text)
        return {"status": "set", "address": address_str}
    except Exception as e:
        return {"error": "Failed to set comment: " + str(e)}

def delete_comment(address_str):
    """Delete all comments at a specific address."""
    if currentProgram is None:
        return {"error": "No program loaded"}

    try:
        addr = currentProgram.getAddressFactory().getAddress(address_str)
        if addr is None:
            return {"error": "Invalid address: " + address_str}

        listing = currentProgram.getListing()
        from ghidra.program.model.listing import CodeUnit

        listing.setComment(addr, CodeUnit.EOL_COMMENT, None)
        listing.setComment(addr, CodeUnit.PRE_COMMENT, None)
        listing.setComment(addr, CodeUnit.POST_COMMENT, None)
        listing.setComment(addr, CodeUnit.PLATE_COMMENT, None)

        return {"status": "deleted", "address": address_str}
    except Exception as e:
        return {"error": "Failed to delete comment: " + str(e)}

if __name__ == "__main__":
    try:
        if len(args) < 1:
            print("---GHIDRA_CLI_START---")
            print(json.dumps({"error": "No command specified"}))
            print("---GHIDRA_CLI_END---")
            sys.exit(1)

        command = args[0]

        if command == "list":
            result = list_comments()
        elif command == "get":
            result = get_comments(args[1] if len(args) > 1 else None)
        elif command == "set":
            text = args[2] if len(args) > 2 else ""
            comment_type = args[3] if len(args) > 3 else "EOL"
            result = set_comment(args[1] if len(args) > 1 else None, text, comment_type)
        elif command == "delete":
            result = delete_comment(args[1] if len(args) > 1 else None)
        else:
            result = {"error": "Unknown command: " + command}

        print("---GHIDRA_CLI_START---")
        print(json.dumps(result))
        print("---GHIDRA_CLI_END---")
    except Exception as e:
        print("---GHIDRA_CLI_START---")
        print(json.dumps({"error": str(e)}))
        print("---GHIDRA_CLI_END---")
