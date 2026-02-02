use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use std::sync::Once;

static BUILD_FIXTURE: Once = Once::new();

fn fixture_dll() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dll_path = manifest
        .join("tests")
        .join("fixtures")
        .join("SampleLib")
        .join("bin")
        .join("Release")
        .join("net8.0")
        .join("SampleLib.dll");

    BUILD_FIXTURE.call_once(|| {
        let csproj = manifest
            .join("tests")
            .join("fixtures")
            .join("SampleLib")
            .join("SampleLib.csproj");

        let status = std::process::Command::new("dotnet")
            .args(["build", csproj.to_str().unwrap(), "-c", "Release"])
            .status()
            .expect("dotnet CLI required for tests");

        assert!(status.success(), "Failed to build SampleLib test fixture");
    });

    assert!(dll_path.exists(), "SampleLib.dll not found at {}", dll_path.display());
    dll_path
}

fn ilspy() -> Command {
    Command::cargo_bin("ilspy").expect("ilspy binary not found")
}

#[test]
fn test_version() {
    ilspy()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ilspy"));
}

#[test]
fn test_help() {
    ilspy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("decompile"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("detect"))
        .stdout(predicate::str::contains("search"));
}

#[test]
fn test_doctor() {
    ilspy()
        .arg("doctor")
        .assert()
        .success();
}

#[test]
fn test_detect_dll() {
    let dll = fixture_dll();
    ilspy()
        .args(["detect", dll.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(".NET"));
}

#[test]
fn test_list_types() {
    let dll = fixture_dll();
    ilspy()
        .args(["list", "types", dll.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("SampleClass"))
        .stdout(predicate::str::contains("SampleEnum"))
        .stdout(predicate::str::contains("SampleStruct"));
}

#[test]
fn test_list_types_json() {
    let dll = fixture_dll();
    ilspy()
        .args(["list", "types", dll.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"fullName\""));
}

#[test]
fn test_list_types_filter() {
    let dll = fixture_dll();
    ilspy()
        .args(["list", "types", dll.to_str().unwrap(), "--filter", "Enum"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SampleEnum"))
        .stdout(predicate::str::contains("SampleClass").not());
}

#[test]
fn test_list_methods() {
    let dll = fixture_dll();
    ilspy()
        .args([
            "list", "methods", dll.to_str().unwrap(),
            "--type", "SampleLib.SampleClass",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Greet"))
        .stdout(predicate::str::contains("Add"))
        .stdout(predicate::str::contains("IsEven"));
}

#[test]
fn test_decompile_full() {
    let dll = fixture_dll();
    ilspy()
        .args(["decompile", dll.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("class SampleClass"))
        .stdout(predicate::str::contains("Greet"));
}

#[test]
fn test_decompile_type() {
    let dll = fixture_dll();
    ilspy()
        .args([
            "decompile", dll.to_str().unwrap(),
            "--type", "SampleLib.SampleClass",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("class SampleClass"))
        .stdout(predicate::str::contains("public string Greet"));
}

#[test]
fn test_decompile_method() {
    let dll = fixture_dll();
    ilspy()
        .args([
            "decompile", dll.to_str().unwrap(),
            "--type", "SampleLib.SampleClass",
            "--method", "Add",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Add"))
        .stdout(predicate::str::contains("return a + b"));
}

#[test]
fn test_search() {
    let dll = fixture_dll();
    ilspy()
        .args(["search", dll.to_str().unwrap(), "Greet"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SampleClass"))
        .stdout(predicate::str::contains("Greet"));
}

#[test]
fn test_info() {
    let dll = fixture_dll();
    ilspy()
        .args(["info", dll.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("SampleLib"));
}

#[test]
fn test_info_json() {
    let dll = fixture_dll();
    ilspy()
        .args(["info", dll.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\""))
        .stdout(predicate::str::contains("\"references\""));
}
