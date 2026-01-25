//! Tests for unimplemented commands to ensure graceful error messages.
//!
//! These tests verify that unimplemented commands print a helpful message
//! instead of crashing or panicking.
//!
//! NOTE: Current CLI outputs to stdout with exit 0. This should eventually
//! be changed to stderr with exit 1 for proper error handling.

use assert_cmd::Command;
use predicates::prelude::*;

// Macro reduces boilerplate for unimplemented command tests.
macro_rules! test_unimplemented {
    ($name:ident, $($arg:expr),*) => {
        #[test]
        fn $name() {
            Command::cargo_bin("ghidra").unwrap()
                $(.arg($arg))*
                .assert()
                .success()  // CLI currently exits 0 for unimplemented
                .stdout(predicate::str::contains("not yet implemented")
                    .or(predicate::str::contains("Command not yet implemented")));
        }
    };
}

// Program commands (use --program flag)
test_unimplemented!(test_program_close, "program", "close", "--program", "test");
test_unimplemented!(test_program_delete, "program", "delete", "--program", "test");
test_unimplemented!(test_program_info, "program", "info", "--program", "test");
test_unimplemented!(test_program_export, "program", "export", "--program", "test", "json");

// Symbol commands (use positional args)
test_unimplemented!(test_symbol_list, "symbol", "list");
test_unimplemented!(test_symbol_get, "symbol", "get", "0x1000");
test_unimplemented!(test_symbol_create, "symbol", "create", "0x1000", "test_sym");
test_unimplemented!(test_symbol_delete, "symbol", "delete", "test_sym");
test_unimplemented!(test_symbol_rename, "symbol", "rename", "test_sym", "new_sym");

// Type commands (use positional args)
test_unimplemented!(test_type_list, "type", "list");
test_unimplemented!(test_type_get, "type", "get", "int");
test_unimplemented!(test_type_create, "type", "create", "my_struct");
test_unimplemented!(test_type_apply, "type", "apply", "0x1000", "int");

// Comment commands (use positional args)
test_unimplemented!(test_comment_list, "comment", "list");
test_unimplemented!(test_comment_get, "comment", "get", "0x1000");
test_unimplemented!(test_comment_set, "comment", "set", "0x1000", "test");
test_unimplemented!(test_comment_delete, "comment", "delete", "0x1000");

// Find commands
test_unimplemented!(test_find_string, "find", "string", "test");
test_unimplemented!(test_find_bytes, "find", "bytes", "deadbeef");
test_unimplemented!(test_find_function, "find", "function", "test");
test_unimplemented!(test_find_calls, "find", "calls", "test");
test_unimplemented!(test_find_crypto, "find", "crypto");
test_unimplemented!(test_find_interesting, "find", "interesting");

// Graph commands
test_unimplemented!(test_graph_calls, "graph", "calls");
test_unimplemented!(test_graph_callers, "graph", "callers", "main");
test_unimplemented!(test_graph_callees, "graph", "callees", "main");
test_unimplemented!(test_graph_export, "graph", "export", "dot");

// Diff commands
test_unimplemented!(test_diff_programs, "diff", "programs", "prog1", "prog2");
test_unimplemented!(test_diff_functions, "diff", "functions");

// Patch commands
test_unimplemented!(test_patch_bytes, "patch", "bytes", "0x1000", "deadbeef");
test_unimplemented!(test_patch_nop, "patch", "nop", "0x1000");
test_unimplemented!(test_patch_export, "patch", "export", "--output", "test.bin");

// Script commands
test_unimplemented!(test_script_run, "script", "run", "test.py");
test_unimplemented!(test_script_python, "script", "python", "test.py");
test_unimplemented!(test_script_java, "script", "java", "test.java");
test_unimplemented!(test_script_list, "script", "list");

// Disasm command
test_unimplemented!(test_disasm, "disasm", "0x1000");

// Other commands
test_unimplemented!(test_batch, "batch", "test.txt");
test_unimplemented!(test_stats, "stats");
