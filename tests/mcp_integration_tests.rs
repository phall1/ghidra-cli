use serial_test::serial;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn run_mcp_exchange(messages: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ghidra"))
        .arg("mcp")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start MCP server");

    {
        let mut stdin = child.stdin.take().expect("stdin unavailable");
        for msg in messages {
            let line = serde_json::to_string(msg).expect("serialize message");
            writeln!(stdin, "{}", line).expect("write MCP message");
        }
        stdin.flush().expect("flush MCP stdin");
    }

    std::thread::sleep(Duration::from_millis(400));
    let _ = child.kill();
    let output = child.wait_with_output().expect("wait for MCP child output");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect()
}

#[test]
#[serial]
fn test_mcp_initialize_and_tools_list() {
    require_ghidra!();
    let _harness = harness();

    let messages = vec![
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1.0"}
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
    ];

    let responses = run_mcp_exchange(&messages);
    assert!(!responses.is_empty(), "MCP should emit JSON responses");

    let init = responses
        .iter()
        .find(|v| v.get("id").and_then(|id| id.as_i64()) == Some(1))
        .expect("missing initialize response");
    assert!(
        init.get("result").is_some(),
        "initialize should return result: {}",
        init
    );

    let tools_list = responses
        .iter()
        .find(|v| v.get("id").and_then(|id| id.as_i64()) == Some(2))
        .expect("missing tools/list response");
    let tools = tools_list
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("tools/list must return tools array");

    assert!(
        tools.len() >= 70,
        "expected >=70 tools, got {}",
        tools.len()
    );

    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"list_functions"));
    assert!(names.contains(&"decompile_function"));
    assert!(names.contains(&"rename_variable"));
    assert!(names.contains(&"get_pcode_at"));
}

#[test]
#[serial]
fn test_mcp_tool_call_and_error_shape() {
    require_ghidra!();
    let _harness = harness();

    let messages = vec![
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1.0"}
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_functions",
                "arguments": {"limit": 5}
            }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "create_structure",
                "arguments": {}
            }
        }),
    ];

    let responses = run_mcp_exchange(&messages);
    assert!(!responses.is_empty(), "MCP should emit JSON responses");

    let ok_call = responses
        .iter()
        .find(|v| v.get("id").and_then(|id| id.as_i64()) == Some(3))
        .expect("missing tools/call success response");
    let content = ok_call
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .expect("tools/call should return content array");
    assert!(
        !content.is_empty(),
        "successful tool call should have content"
    );

    let err_call = responses
        .iter()
        .find(|v| v.get("id").and_then(|id| id.as_i64()) == Some(4))
        .expect("missing tools/call invalid args response");

    let has_error_obj = err_call.get("error").is_some();
    let has_is_error_flag = err_call
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    assert!(
        has_error_obj || has_is_error_flag,
        "invalid tool call should produce protocol error or isError result: {}",
        err_call
    );
}
