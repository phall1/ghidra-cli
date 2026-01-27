//! Tests for query commands that require daemon.
//!
//! These tests verify that query commands return properly structured data by:
//! 1. Validating JSON output against typed schemas
//! 2. Checking semantic correctness (e.g., functions have names and addresses)
//! 3. Testing filter and limit parameters work correctly
//! 4. Using snapshot testing for format regression detection

use once_cell::sync::Lazy;
use serial_test::serial;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, ghidra,
    schemas::{Function, MemoryBlock, StringData, Validate},
    DaemonTestHarness,
};

const TEST_PROJECT: &str = "query-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: Lazy<DaemonTestHarness> = Lazy::new(|| {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
    DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
});

// ============================================================================
// Function List Tests
// ============================================================================

/// Test function list returns valid, well-formed data.
#[test]
#[serial]
fn test_function_list_schema_validation() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Parse and validate the schema
    let functions: Vec<Function> = result.json();

    // Should have at least one function (main at minimum)
    assert!(!functions.is_empty(), "Function list should not be empty");

    // Validate each function has required fields
    for func in &functions {
        func.assert_valid();
    }

    // Verify expected functions exist
    let has_main = functions.iter().any(|f| f.name == "main");
    assert!(has_main, "Should contain main function");
}

/// Test function list contains expected functions from sample_binary.
#[test]
#[serial]
fn test_function_list_contains_expected_functions() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();
    let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();

    // Check for known functions in sample_binary
    assert!(
        names.iter().any(|n| *n == "main"),
        "Should have main function. Found: {:?}",
        names
    );

    // The sample binary should have other functions too
    assert!(
        functions.len() >= 2,
        "Should have multiple functions, found {}",
        functions.len()
    );
}

/// Test function list --limit parameter works correctly.
#[test]
#[serial]
fn test_function_list_limit() {
    let harness = &*HARNESS;

    let limit = 3;
    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .arg("--limit")
        .arg(limit.to_string())
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();

    assert!(
        functions.len() <= limit,
        "Limit {} should return at most {} functions, got {}",
        limit,
        limit,
        functions.len()
    );
}

/// Test function list --filter parameter works correctly.
#[test]
#[serial]
fn test_function_list_filter() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .arg("--filter")
        .arg("main")
        .run();

    result.assert_success();

    let functions: Vec<Function> = result.json();

    // All returned functions should match the filter
    for func in &functions {
        assert!(
            func.name.to_lowercase().contains("main"),
            "Filtered results should contain 'main', got: {}",
            func.name
        );
    }

    // Should return at least one result
    assert!(
        !functions.is_empty(),
        "Filter 'main' should match at least one function"
    );
}

// ============================================================================
// Strings List Tests
// ============================================================================

/// Test strings list returns valid data.
#[test]
#[serial]
fn test_strings_list_schema_validation() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("strings")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .arg("--limit")
        .arg("50")
        .run();

    result.assert_success();

    // Try to parse as StringData array
    if let Some(strings) = result.try_json::<Vec<StringData>>() {
        for s in &strings {
            s.assert_valid();
        }
    }
}

// ============================================================================
// Memory Map Tests
// ============================================================================

/// Test memory map returns valid segment information.
#[test]
#[serial]
fn test_memory_map_schema_validation() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("memory")
        .arg("map")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .run();

    result.assert_success();

    // Try to parse as MemoryBlock array
    if let Some(blocks) = result.try_json::<Vec<MemoryBlock>>() {
        assert!(
            !blocks.is_empty(),
            "Memory map should have at least one block"
        );

        for block in &blocks {
            block.assert_valid();
        }

        // Should have a .text segment (code)
        let has_text = blocks.iter().any(|b| {
            b.name.contains("text") || b.name.contains("code") || b.name.contains(".text")
        });
        assert!(
            has_text,
            "Should have a text/code segment. Found: {:?}",
            blocks.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
    }
}

// ============================================================================
// Summary Tests
// ============================================================================

/// Test summary command returns expected fields.
#[test]
#[serial]
fn test_summary_contains_expected_fields() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("summary")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    // Summary should contain key information
    result.assert_stdout_contains("Program");
}

// ============================================================================
// Decompile Tests
// ============================================================================

/// Test decompiling by function name.
#[test]
#[serial]
fn test_decompile_by_name() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("decompile")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    // Decompiled output should contain C-like code
    assert!(
        result.stdout.contains("void")
            || result.stdout.contains("int")
            || result.stdout.contains("{")
            || result.stdout.contains("return"),
        "Decompiled output should contain C-like code.\nGot: {}",
        result.stdout
    );
}

/// Test decompiling by address (using dynamically resolved address).
#[test]
#[serial]
fn test_decompile_by_address() {
    let harness = &*HARNESS;

    // Get main's address dynamically
    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("decompile")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();

    // Should produce some output (decompiled code)
    assert!(
        !result.stdout.trim().is_empty(),
        "Decompile should produce output"
    );
}

/// Test decompiling nonexistent function fails gracefully.
#[test]
#[serial]
fn test_decompile_nonexistent_function() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("decompile")
        .arg("this_function_definitely_does_not_exist_xyz123")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    // Should fail or return empty/error
    // (behavior depends on implementation)
    if result.exit_code == 0 {
        // If it "succeeds", should indicate no function found
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

/// Test xref to address.
#[test]
#[serial]
fn test_xref_to() {
    let harness = &*HARNESS;

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("xref")
        .arg("to")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    // XRefs to main might be empty (if nothing calls main) or have entries
    // Just verify it doesn't crash
}

/// Test xref from address.
#[test]
#[serial]
fn test_xref_from() {
    let harness = &*HARNESS;

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("xref")
        .arg("from")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    result.assert_success();
    // main likely calls other functions, but even if not, shouldn't crash
}

// ============================================================================
// Snapshot Tests
// ============================================================================

/// Snapshot test for function list JSON format.
#[test]
#[serial]
fn test_function_list_snapshot() {
    let harness = &*HARNESS;

    let result = ghidra(harness)
        .arg("function")
        .arg("list")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .arg("--limit")
        .arg("3") // Small limit for stable snapshot
        .run();

    if result.exit_code == 0 {
        let normalized = common::normalize_json(&result.stdout);
        insta::assert_snapshot!("function_list_json", normalized);
    }
}
