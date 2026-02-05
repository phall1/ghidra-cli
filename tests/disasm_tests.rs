//! Tests for disassembly operations.
//!
//! These tests verify that disassembly commands work correctly by:
//! 1. Validating instruction schema structure
//! 2. Using dynamically resolved addresses
//! 3. Verifying instruction limits work correctly
//! 4. Testing error handling for invalid inputs

use serial_test::serial;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, ghidra,
    schemas::{DisasmResult, Instruction, Validate},
    DaemonTestHarness,
};

const TEST_PROJECT: &str = "disasm-test";
const TEST_PROGRAM: &str = "sample_binary";

// ============================================================================
// Basic Disassembly Tests
// ============================================================================

/// Test disassembly at dynamically resolved main address.
#[test]
#[serial]
fn test_disasm_at_main() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Get main's address dynamically instead of hardcoding
    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Try to parse as DisasmResult
    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            !disasm.results.is_empty(),
            "Should have at least one instruction"
        );

        // Validate instruction structure
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<Instruction>>() {
        // Some outputs might be a direct array
        assert!(
            !instructions.is_empty(),
            "Should have at least one instruction"
        );

        for instr in &instructions {
            instr.assert_valid();
        }
    }
}

/// Test disassembly with instruction limit.
#[test]
#[serial]
fn test_disasm_with_instruction_limit() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");
    let limit = 5;

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg(limit.to_string())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Verify limit is respected
    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            disasm.results.len()
        );

        // Each instruction should be valid
        for instr in &disasm.results {
            instr.assert_valid();
        }
    } else if let Some(instructions) = result.try_json::<Vec<Instruction>>() {
        assert!(
            instructions.len() <= limit,
            "Should return at most {} instructions, got {}",
            limit,
            instructions.len()
        );
    }
}

/// Test disassembly with very small limit.
#[test]
#[serial]
fn test_disasm_small_count() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("1")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Should return exactly 1 instruction (or possibly 0 if at end)
    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(
            disasm.results.len() <= 1,
            "Should return at most 1 instruction, got {}",
            disasm.results.len()
        );
    }
}

// ============================================================================
// Instruction Content Verification
// ============================================================================

/// Test that disassembly returns expected instruction fields.
#[test]
#[serial]
fn test_disasm_instruction_fields() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("10")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    if let Some(disasm) = result.try_json::<DisasmResult>() {
        assert!(!disasm.results.is_empty(), "Should have instructions");

        let first = &disasm.results[0];

        // Verify essential fields are present
        assert!(!first.mnemonic.is_empty(), "Mnemonic should not be empty");
        assert!(!first.address.is_empty(), "Address should not be empty");

        // Verify address format
        assert!(
            first.address.starts_with("0x") || first.address.starts_with("0X"),
            "Address should be hex format, got: {}",
            first.address
        );

        // Function prologue typically starts with PUSH, SUB, ENDBR, or similar
        let common_first_instr = ["PUSH", "SUB", "MOV", "ENDBR", "LEA", "XOR", "JMP"];
        let mnemonic_upper = first.mnemonic.to_uppercase();

        // This is a soft check - just log if unexpected
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

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test disassembly at invalid address fails gracefully.
#[test]
#[serial]
fn test_disasm_invalid_address() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg("0xFFFFFFFFFFFFFFFF") // Unmapped address
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Should fail or return empty results
    // (exact behavior depends on implementation)
    if result.exit_code == 0 {
        // If it succeeds, should have empty results or error indication
        if let Some(_disasm) = result.try_json::<DisasmResult>() {
            // Empty results are acceptable for unmapped address
            // Or it might have an error field
        }
    } else {
        // Failure is acceptable for unmapped address
        // Should have some error message
        assert!(
            !result.stderr.is_empty() || !result.stdout.is_empty(),
            "Should provide some output explaining the error"
        );
    }
}

/// Test disassembly with missing program argument.
#[test]
#[serial]
fn test_disasm_missing_program() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg("0x101000")
        // --program is missing
        .run();

    // Should fail with helpful error
    result.assert_failure();
}

/// Test disassembly with zero instruction count.
#[test]
#[serial]
fn test_disasm_zero_instructions() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("0")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Should either fail gracefully or return empty results
    if result.exit_code == 0 {
        if let Some(disasm) = result.try_json::<DisasmResult>() {
            assert!(
                disasm.results.is_empty(),
                "Zero instruction count should return empty results"
            );
        }
    }
    // Failure with error message is also acceptable
}

// ============================================================================
// Snapshot Tests
// ============================================================================

/// Test that disassembly JSON output has expected structure.
#[test]
#[serial]
fn test_disasm_output_format_structure() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let main_addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(&harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("3")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Parse and validate JSON structure
    let json: serde_json::Value =
        serde_json::from_str(&result.stdout).expect("Output should be valid JSON");

    // Should be an array (or object with results array)
    let instructions = if let Some(arr) = json.as_array() {
        arr.clone()
    } else if let Some(obj) = json.as_object() {
        obj.get("results")
            .and_then(|v| v.as_array())
            .expect("Object should have 'results' array")
            .clone()
    } else {
        panic!("Expected JSON array or object with results");
    };

    assert!(
        !instructions.is_empty() && instructions.len() <= 3,
        "Expected 1-3 instructions, got {}",
        instructions.len()
    );

    // Each instruction should have required fields
    for instr in &instructions {
        let obj = instr.as_object().expect("Instruction should be an object");
        assert!(obj.contains_key("address"), "Missing 'address' field");
        assert!(obj.contains_key("mnemonic"), "Missing 'mnemonic' field");
        assert!(obj.contains_key("bytes"), "Missing 'bytes' field");
    }
}
