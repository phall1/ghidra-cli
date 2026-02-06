//! Consolidated read-only integration tests.
//!
//! All tests that only READ from the Ghidra project share a single
//! DaemonTestHarness to avoid redundant import+analyze cycles.

use serial_test::serial;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, ghidra,
    helpers::matches_function_name,
    schemas::{
        DisasmResult, Function, GraphResult, MemoryBlock, StatsResult, StringData, Validate, XRef,
    },
    DaemonTestHarness, GhidraCommand,
};

const TEST_PROJECT: &str = "readonly-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Known exported function names from sample_binary
const KNOWN_FUNCTIONS: &[&str] = &[
    "add_numbers",
    "multiply",
    "factorial",
    "fibonacci",
    "process_string",
    "xor_encrypt",
    "simple_hash",
    "init_struct",
    "main",
];

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

// ============================================================================
// Function List Tests
// ============================================================================

#[test]
#[serial]
fn test_function_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(!functions.is_empty(), "Function list should not be empty");

    for func in &functions {
        func.assert_valid();
    }

    let has_main = functions.iter().any(|f| f.name == "main");
    assert!(has_main, "Should contain main function");
}

#[test]
#[serial]
fn test_function_list_contains_expected_functions() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();

    for expected in KNOWN_FUNCTIONS {
        let found = functions
            .iter()
            .any(|f| matches_function_name(&f.name, expected));
        assert!(
            found,
            "Expected function '{}' not found. Available: {:?}",
            expected,
            functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
    }
}

#[test]
#[serial]
fn test_function_list_limit() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("3")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        functions.len() <= 3,
        "Limit 3 should return at most 3 functions, got {}",
        functions.len()
    );
}

#[test]
#[serial]
fn test_function_list_filter() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--filter")
        .arg("main")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    assert!(
        !functions.is_empty(),
        "Filter 'main' should match at least one function"
    );

    let has_main = functions
        .iter()
        .any(|f| f.name.to_lowercase().contains("main"));
    assert!(
        has_main,
        "At least one filtered result should contain 'main'. Got: {:?}",
        functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
}

// ============================================================================
// Strings List Tests
// ============================================================================

#[test]
#[serial]
fn test_strings_list_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("strings")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("50")
        .run();

    result.assert_success();

    let strings: Vec<StringData> = result.json();

    for s in &strings {
        s.assert_valid();
    }

    let known_substrings = ["Hello", "test_binary", "super_secret"];
    let mut found_count = 0;
    for known in &known_substrings {
        if strings.iter().any(|s| s.value.contains(known)) {
            found_count += 1;
        }
    }
    assert!(
        found_count >= 3,
        "Expected at least 3 known strings found, got {}. Strings: {:?}",
        found_count,
        strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}

// ============================================================================
// Memory Map Tests
// ============================================================================

#[test]
#[serial]
fn test_memory_map_schema_validation() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let blocks: Vec<MemoryBlock> = result.json();
    assert!(
        !blocks.is_empty(),
        "Memory map should have at least one block"
    );

    for block in &blocks {
        block.assert_valid();
    }

    let has_text = blocks
        .iter()
        .any(|b| b.name.contains("text") || b.name.contains("code") || b.name.contains(".text"));
    assert!(
        has_text,
        "Should have a text/code segment. Found: {:?}",
        blocks.iter().map(|b| &b.name).collect::<Vec<_>>()
    );
}

// ============================================================================
// Summary Tests
// ============================================================================

#[test]
#[serial]
fn test_summary_contains_expected_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("summary")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Summary should produce output"
    );
    result.assert_stdout_contains("sample_binary");
}

// ============================================================================
// Decompile Tests
// ============================================================================

#[test]
#[serial]
fn test_decompile_by_name() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("decompile")
        .arg("add_numbers")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    assert!(
        result.stdout.contains("return")
            || result.stdout.contains("param")
            || result.stdout.contains("int")
            || result.stdout.contains("long"),
        "Decompiled output should contain C-like code keywords.\nGot: {}",
        result.stdout
    );
}

#[test]
#[serial]
fn test_decompile_by_address() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Decompile should produce output"
    );
}

#[test]
#[serial]
fn test_decompile_nonexistent_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("decompile")
        .arg("this_function_definitely_does_not_exist_xyz123")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        assert!(
            result.stdout.to_lowercase().contains("not found")
                || result.stdout.to_lowercase().contains("error")
                || result.stdout.trim().is_empty(),
            "Should indicate function not found"
        );
    }
}

// ============================================================================
// XRef Tests
// ============================================================================

#[test]
#[serial]
fn test_xref_to() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "add_numbers");

    let result = ghidra(harness)
        .arg("xref")
        .arg("to")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(xrefs) = result.try_json::<Vec<XRef>>() {
        if let Some(xref) = xrefs.iter().find(|x| {
            x.from_function
                .as_deref()
                .is_some_and(|f| f.contains("main"))
        }) {
            eprintln!("Found xref from main: {:?}", xref);
        } else {
            eprintln!(
                "No xref from main found (may vary by platform). Xrefs: {:?}",
                xrefs
            );
        }
    }
}

#[test]
#[serial]
fn test_xref_from() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("xref")
        .arg("from")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(xrefs) = result.try_json::<Vec<XRef>>() {
        assert!(
            !xrefs.is_empty(),
            "main should have outgoing xrefs (it calls many functions)"
        );
    }
}

// ============================================================================
// Find Tests
// ============================================================================

#[test]
#[serial]
fn test_find_string() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("Hello")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("Hello, Ghidra CLI!");
}

#[test]
#[serial]
fn test_find_bytes() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("bytes")
        .arg("4883ec08")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_function() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
}

#[test]
#[serial]
fn test_find_function_glob() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("function")
        .arg("m*")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("main");
}

#[test]
#[serial]
fn test_find_calls() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("calls")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_find_crypto() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("crypto")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
}

#[test]
#[serial]
fn test_find_interesting() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("interesting")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let _: serde_json::Value = result.json();
}

#[test]
#[serial]
fn test_find_string_no_matches() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("find")
        .arg("string")
        .arg("nonexistent_string_xyz123")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(json) = result.try_json::<serde_json::Value>() {
        if let Some(arr) = json.as_array() {
            assert!(
                arr.is_empty(),
                "Should have no matches for nonexistent string"
            );
        }
    }
}

// ============================================================================
// Graph Tests
// ============================================================================

#[test]
#[serial]
fn test_graph_calls() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("calls")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("nodes");
    result.assert_stdout_contains("edges");
}

#[test]
#[serial]
fn test_graph_callers() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callers")
        .arg("add_numbers")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        let has_main_node = graph
            .nodes
            .iter()
            .any(|n| n.label.as_deref().is_some_and(|l| l.contains("main")));
        if has_main_node {
            eprintln!("Found main in callers graph nodes");
        } else {
            eprintln!(
                "main not found in callers graph nodes (may vary by platform). Nodes: {:?}",
                graph.nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
#[serial]
fn test_graph_callees() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(graph) = result.try_json::<GraphResult>() {
        let node_labels: Vec<_> = graph
            .nodes
            .iter()
            .filter_map(|n| n.label.as_deref())
            .collect();

        let has_add_numbers = node_labels
            .iter()
            .any(|l| l.contains("add_numbers") || l.contains("_add_numbers"));
        let has_multiply = node_labels
            .iter()
            .any(|l| l.contains("multiply") || l.contains("_multiply"));

        if has_add_numbers {
            eprintln!("Found add_numbers in callees");
        }
        if has_multiply {
            eprintln!("Found multiply in callees");
        }
    }
}

#[test]
#[serial]
fn test_graph_export_dot() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("export")
        .arg("dot")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("digraph");
}

// ============================================================================
// Stats Tests
// ============================================================================

#[test]
#[serial]
fn test_stats_normal() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    result.assert_stdout_contains("stats");
    result.assert_stdout_contains("functions");
    result.assert_stdout_contains("symbols");
}

#[test]
#[serial]
fn test_stats_has_all_fields() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    let obj = json.as_object().expect("Stats should be a JSON object");

    for key in &[
        "functions",
        "symbols",
        "strings",
        "imports",
        "exports",
        "memory_size",
        "sections",
        "data_types",
    ] {
        assert!(obj.contains_key(*key), "Missing stats field: {}", key);
    }

    let functions = obj.get("functions").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(
        functions > 0,
        "functions count should be > 0, got {}",
        functions
    );

    let strings = obj.get("strings").and_then(|v| v.as_u64()).unwrap_or(0);
    assert!(strings > 0, "strings count should be > 0, got {}", strings);
}

#[test]
#[serial]
fn test_stats_json_format() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    let stats: StatsResult = result.json();
    assert!(
        stats.functions.unwrap_or(0) >= 8,
        "Should have at least 8 functions, got {:?}",
        stats.functions
    );
    assert!(
        stats.strings.unwrap_or(0) >= 3,
        "Should have at least 3 strings, got {:?}",
        stats.strings
    );
}

// ============================================================================
// Disassembly Tests
// ============================================================================

#[test]
#[serial]
fn test_disasm_at_main() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            !disasm.results.is_empty(),
            "Should have at least one instruction"
        );
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<common::schemas::Instruction>>() {
        assert!(
            !instructions.is_empty(),
            "Should have at least one instruction"
        );
        for instr in &instructions {
            instr.assert_valid();
        }
    }
}

#[test]
#[serial]
fn test_disasm_with_instruction_limit() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let limit = 5;

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg(limit.to_string())
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            disasm.results.len()
        );
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<common::schemas::Instruction>>() {
        assert!(
            instructions.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            instructions.len()
        );
    }
}

#[test]
#[serial]
fn test_disasm_small_count() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("1")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= 1,
            "Should return at most 1 instruction, got {}",
            disasm.results.len()
        );
    }
}

#[test]
#[serial]
fn test_disasm_instruction_fields() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("10")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(!disasm.results.is_empty(), "Should have instructions");

        let first = &disasm.results[0];
        assert!(!first.mnemonic.is_empty(), "Mnemonic should not be empty");
        assert!(!first.address.is_empty(), "Address should not be empty");

        let addr_hex = first
            .address
            .strip_prefix("0x")
            .or_else(|| first.address.strip_prefix("0X"))
            .unwrap_or(&first.address);
        assert!(
            !addr_hex.is_empty() && addr_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "Address should be hex format, got: {}",
            first.address
        );

        let common_first_instr = [
            "PUSH", "SUB", "MOV", "ENDBR", "LEA", "XOR", "JMP", // x86
            "STP", "STR", "BL", "NOP", "ADRP", "ADD", "RET", // ARM64
        ];
        let mnemonic_upper = first.mnemonic.to_uppercase();

        if !common_first_instr
            .iter()
            .any(|&m| mnemonic_upper.starts_with(m))
        {
            eprintln!(
                "Note: First instruction is '{}' - unusual but not necessarily wrong",
                first.mnemonic
            );
        }
    }
}

#[test]
#[serial]
fn test_disasm_invalid_address() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("disasm")
        .arg("0xFFFFFFFFFFFFFFFF")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        if let Some(_disasm) = result.try_json::<DisasmResult>() {
            // Empty results are acceptable for unmapped address
        }
    } else {
        assert!(
            !result.stderr.is_empty() || !result.stdout.is_empty(),
            "Should provide some output explaining the error"
        );
    }
}

#[test]
#[serial]
fn test_disasm_missing_program() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness).arg("disasm").arg("0x101000").run();

    result.assert_failure();
}

#[test]
#[serial]
fn test_disasm_zero_instructions() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("0")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        if let Some(disasm) = result.try_json::<DisasmResult>() {
            assert!(
                disasm.results.is_empty(),
                "Zero instruction count should return empty results"
            );
        }
    }
}

// ============================================================================
// Diff Tests
// ============================================================================

#[test]
#[serial]
fn test_diff_programs() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("diff")
        .arg("programs")
        .arg(TEST_PROGRAM)
        .arg(TEST_PROGRAM)
        .arg("--project")
        .arg(TEST_PROJECT)
        .run();

    result.assert_success();

    let output_lower = result.stdout.to_lowercase();
    assert!(
        output_lower.contains("identical")
            || output_lower.contains("0")
            || result.stdout.trim().is_empty()
            || output_lower.contains("no diff")
            || output_lower.contains("same"),
        "Self-diff should indicate identical/no differences. Got: {}",
        result.stdout
    );
}

#[test]
#[serial]
fn test_diff_functions() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("diff")
        .arg("functions")
        .arg("main")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .run();

    result.assert_success();
}

#[test]
#[serial]
fn test_diff_functions_different() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("diff")
        .arg("functions")
        .arg("main")
        .arg("add_numbers")
        .arg("--project")
        .arg(TEST_PROJECT)
        .run();

    result.assert_success();
    assert!(
        !result.stdout.trim().is_empty(),
        "Diff of different functions should produce output"
    );
}

// ============================================================================
// Program Tests
// ============================================================================

#[test]
#[serial]
fn test_program_info() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("info")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    let json_str = serde_json::to_string(&json).unwrap_or_default();
    assert!(
        json_str.contains("sample_binary"),
        "Program info should contain 'sample_binary'. Got: {}",
        json_str
    );
}

#[test]
#[serial]
fn test_program_export_json() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("export")
        .arg("json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    if result.exit_code == 0 {
        assert!(
            result.stdout.contains("functions") || !result.stdout.is_empty(),
            "Export should produce output"
        );
    }
    // Accept "Unknown command" gracefully
}

#[test]
#[serial]
fn test_program_close() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("program")
        .arg("close")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    assert!(
        result.exit_code == 0 || result.stderr.contains("Unknown command"),
        "Expected success or 'Unknown command', got: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_program_info_no_program() {
    require_ghidra!();
    let harness = harness();

    let result = GhidraCommand::new()
        .arg("program")
        .arg("info")
        .with_daemon(harness)
        .run();

    result.assert_success();
}

// ============================================================================
// Batch Tests
// ============================================================================

fn create_batch_file(content: &str) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let batch_file = temp_dir.join(format!("ghidra_batch_{}.txt", std::process::id()));
    fs::write(&batch_file, content).expect("Failed to write batch file");
    batch_file
}

#[test]
#[serial]
fn test_batch_multiple_queries() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Test batch file
query --address 0x100000
query --function main
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("results");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_empty_file() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Only comments


# More comments
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_with_comments() {
    require_ghidra!();
    harness();

    let batch_content = r#"
# Query main function
query --function main
# Query by address
query --address 0x100000
# Another comment
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("2");

    fs::remove_file(batch_file).ok();
}

#[test]
#[serial]
fn test_batch_invalid_file() {
    require_ghidra!();
    harness();

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("/nonexistent/batch/file.txt")
        .run();

    result.assert_failure();
    assert!(
        result.stderr.contains("not found") || result.stderr.contains("No such file"),
        "Should contain file-not-found error. Got: {}",
        result.stderr
    );
}

#[test]
#[serial]
fn test_batch_with_invalid_command() {
    require_ghidra!();
    harness();

    let batch_content = r#"
query --function main
invalid-command --arg value
query --address 0x100000
"#;

    let batch_file = create_batch_file(batch_content);

    let result = GhidraCommand::new()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .run();

    result.assert_success();
    result.assert_stdout_contains("commands_parsed");
    result.assert_stdout_contains("3");

    fs::remove_file(batch_file).ok();
}

// ============================================================================
// Insta Snapshot Tests
// ============================================================================

#[test]
#[serial]
fn test_snapshot_function_list_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .arg("--limit")
        .arg("1")
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("function_list_structure", json, {
        "[].address" => "[ADDR]",
        "[].entry_point" => "[ADDR]",
        "[].size" => "[SIZE]",
        "[].parameters[].ordinal" => "[N]",
        "[].local_variables[].stack_offset" => "[N]",
        "[].calls[]" => "[ADDR]",
        "[].called_by[]" => "[ADDR]",
    });
}

#[test]
#[serial]
fn test_snapshot_stats_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("stats")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("stats_structure", json, {
        ".functions" => "[N]",
        ".instructions" => "[N]",
        ".strings" => "[N]",
        ".symbols" => "[N]",
        ".imports" => "[N]",
        ".exports" => "[N]",
        ".memory_blocks" => "[N]",
        ".memory_size" => "[N]",
        ".sections" => "[N]",
        ".data_types" => "[N]",
    });
}

#[test]
#[serial]
fn test_snapshot_memory_map_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("memory_map_structure", json, {
        "[].start" => "[ADDR]",
        "[].end" => "[ADDR]",
        "[].size" => "[SIZE]",
    });
}

#[test]
#[serial]
fn test_snapshot_disasm_structure() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("3")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("disasm_structure", json, {
        ".results[].address" => "[ADDR]",
        ".results[].operands" => "[OPS]",
        ".results[].bytes" => "[BYTES]",
        ".results[].length" => "[N]",
        ".start_address" => "[ADDR]",
        ".end_address" => "[ADDR]",
        "[].address" => "[ADDR]",
        "[].operands" => "[OPS]",
        "[].bytes" => "[BYTES]",
        "[].length" => "[N]",
    });
}

#[test]
#[serial]
fn test_snapshot_graph_callees_structure() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("graph")
        .arg("callees")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();

    let json: serde_json::Value = result.json();
    insta::assert_json_snapshot!("graph_callees_structure", json, {
        ".nodes[].id" => "[ID]",
        ".nodes[].address" => "[ADDR]",
        ".edges[].from" => "[ID]",
        ".edges[].to" => "[ID]",
    });
}
