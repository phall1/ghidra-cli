//! Structured bridge errors for agent-driven recovery.
//!
//! The Java bridge returns errors as `{status: "error", message: "..."}` —
//! a single English string. That's useless to an LLM trying to decide what
//! to do next: it has to parse English to figure out "did this fail because
//! no program is loaded? because the address is malformed? because the
//! bridge is unreachable?"
//!
//! This module classifies those messages into a finite enum of error codes
//! and attaches hints + a suggested next tool. The MCP layer (`src/mcp`)
//! serializes the result as JSON so agents see structured payloads instead
//! of free-text errors.
//!
//! Today the classification is Rust-side pattern matching on the message
//! string the Java bridge sent. That's fragile by design: when we see
//! misclassifications in the wild, we add patterns here; eventually we push
//! the codes upstream into the Java bridge itself (out of scope for now).

use serde::Serialize;
use std::fmt;

/// Finite enumeration of error categories an agent can branch on.
///
/// `snake_case` on the wire so it reads naturally in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeErrorCode {
    /// A query/write was attempted but no program is open in the bridge.
    NoProgramLoaded,
    /// The named program does not exist in the project.
    ProgramNotFound,
    /// The named function (by name or address) does not exist.
    FunctionNotFound,
    /// The named symbol does not exist.
    SymbolNotFound,
    /// The named type does not exist.
    TypeNotFound,
    /// An address could not be parsed or resolved.
    AddressInvalid,
    /// Required argument missing or argument failed validation.
    InvalidArgs,
    /// The bridge does not know this command name.
    UnknownCommand,
    /// A write/mutation handler threw. Includes the underlying Java exception
    /// message. Often recoverable by retrying with different inputs.
    WriteFailed,
    /// Could not establish a TCP connection to the bridge.
    BridgeUnreachable,
    /// Bridge accepted the connection but did not respond in time.
    BridgeTimeout,
    /// Local I/O error (socket write/read, JSON parse) — not from the bridge.
    Transport,
    /// Java bridge returned an error we don't have a pattern for yet.
    Unknown,
}

/// Structured bridge error. Carries everything an agent (or human) needs to
/// decide what to do next without parsing English.
#[derive(Debug, Clone, Serialize)]
pub struct BridgeError {
    pub code: BridgeErrorCode,
    pub message: String,
    /// True if the agent can plausibly recover by calling a different tool
    /// or retrying with different arguments. False for things like
    /// `UnknownCommand` or `Transport` errors that signal a programming bug
    /// or a dead bridge.
    pub recoverable: bool,
    /// Human-readable hint about *why* this failed and how to fix it. Aimed
    /// at the LLM, not the end-user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// MCP tool name the agent should consider calling next.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_next_tool: Option<String>,
}

impl BridgeError {
    /// Construct from a raw message string returned by the Java bridge.
    ///
    /// Inference is best-effort string matching. Unknown patterns map to
    /// [`BridgeErrorCode::Unknown`] with `recoverable: false`. As we observe
    /// new patterns in practice, add them here and tighten the classifier.
    pub fn from_bridge_message(msg: impl Into<String>) -> Self {
        let message = msg.into();
        let lower = message.to_lowercase();

        // Order matters: more specific patterns first.
        if lower.starts_with("no program loaded") || lower.starts_with("no program currently loaded") {
            return Self {
                code: BridgeErrorCode::NoProgramLoaded,
                recoverable: true,
                hint: Some(
                    "No program is currently open in the Ghidra bridge. Import a binary with `import_binary` or open an existing program in the project with `open_program`. Use `list_programs` to see what's available."
                        .into(),
                ),
                suggested_next_tool: Some("list_programs".into()),
                message,
            };
        }
        if lower.starts_with("program not found") {
            return Self {
                code: BridgeErrorCode::ProgramNotFound,
                recoverable: true,
                hint: Some(
                    "The named program does not exist in the current project. Call `list_programs` to see available program names.".into(),
                ),
                suggested_next_tool: Some("list_programs".into()),
                message,
            };
        }
        if lower.starts_with("function not found") || lower.starts_with("invalid function target") {
            return Self {
                code: BridgeErrorCode::FunctionNotFound,
                recoverable: true,
                hint: Some(
                    "The named function does not exist. `target` may be a function name (e.g. `main`), a hex address (e.g. `0x401000`), or an auto-generated label (e.g. `FUN_00401000`). Use `list_functions` or `find_function` to discover available names."
                        .into(),
                ),
                suggested_next_tool: Some("list_functions".into()),
                message,
            };
        }
        if lower.starts_with("symbol not found") {
            return Self {
                code: BridgeErrorCode::SymbolNotFound,
                recoverable: true,
                hint: Some("The named symbol does not exist. Use `list_symbols` to enumerate.".into()),
                suggested_next_tool: Some("list_symbols".into()),
                message,
            };
        }
        if lower.starts_with("type not found") {
            return Self {
                code: BridgeErrorCode::TypeNotFound,
                recoverable: true,
                hint: Some("The named type does not exist in the program's DataTypeManager. Use `list_types` to enumerate, or `create_type` to define a new one.".into()),
                suggested_next_tool: Some("list_types".into()),
                message,
            };
        }
        if lower.starts_with("invalid address") {
            return Self {
                code: BridgeErrorCode::AddressInvalid,
                recoverable: true,
                hint: Some(
                    "Address could not be parsed or does not resolve. Use a 0x-prefixed hex literal (e.g. `0x401000`) or a function name. For non-default address spaces, use the `space:offset` form."
                        .into(),
                ),
                suggested_next_tool: None,
                message,
            };
        }
        if lower.starts_with("unknown command") {
            return Self {
                code: BridgeErrorCode::UnknownCommand,
                // Not recoverable from the agent's perspective — this signals
                // a Rust/Java protocol mismatch, not a usage error.
                recoverable: false,
                hint: Some(
                    "The CLI sent a command name the Java bridge does not implement. This is a protocol mismatch — file a bug; do not retry.".into(),
                ),
                suggested_next_tool: None,
                message,
            };
        }
        if lower.starts_with("invalid ")
            || lower.ends_with(" required")
            || lower.contains(" required ")
            || lower.contains("required.")
        {
            return Self {
                code: BridgeErrorCode::InvalidArgs,
                recoverable: true,
                hint: Some("Argument validation failed. Re-read the tool's input schema and supply the missing or malformed field.".into()),
                suggested_next_tool: None,
                message,
            };
        }
        if lower.starts_with("failed to ") {
            return Self {
                code: BridgeErrorCode::WriteFailed,
                // Many write paths fail transiently (e.g. address occupied,
                // type mismatch); the agent can usually adjust and retry.
                recoverable: true,
                hint: Some(
                    "A mutation handler threw on the bridge side. The message includes the underlying Java exception. Re-examine arguments; some failures require querying program state first (e.g. `decompile`, `list_symbols`)."
                        .into(),
                ),
                suggested_next_tool: None,
                message,
            };
        }

        Self {
            code: BridgeErrorCode::Unknown,
            recoverable: false,
            hint: Some(
                "Bridge returned an error we do not yet classify. The full message is in `message`. If you see this repeatedly, file a bug so we can add a pattern.".into(),
            ),
            suggested_next_tool: None,
            message,
        }
    }

    /// TCP connect failed: bridge is not listening or wrong port.
    pub fn unreachable(port: u16, cause: impl fmt::Display) -> Self {
        Self {
            code: BridgeErrorCode::BridgeUnreachable,
            recoverable: false,
            hint: Some(format!(
                "Could not connect to the Ghidra bridge on port {port}. The bridge may not be running, or the port file may be stale. Have the user run `ghidra doctor` or restart the bridge via an `import_binary` / `analyze_program` call."
            )),
            suggested_next_tool: None,
            message: format!("Failed to connect to bridge on port {port}: {cause}"),
        }
    }

    /// Bridge accepted connection but did not respond in time.
    pub fn timeout(seconds: u64) -> Self {
        Self {
            code: BridgeErrorCode::BridgeTimeout,
            recoverable: true,
            hint: Some(format!(
                "Bridge did not respond within {seconds}s. Long-running operations (initial analysis of large binaries) can legitimately exceed this. Consider waiting and retrying, or breaking the work into smaller steps."
            )),
            suggested_next_tool: None,
            message: format!("Bridge read timed out after {seconds}s"),
        }
    }

    /// Local I/O / parse failure not attributable to the bridge.
    pub fn transport(cause: impl fmt::Display) -> Self {
        Self {
            code: BridgeErrorCode::Transport,
            recoverable: false,
            hint: Some(
                "Local transport error (socket I/O, JSON encode/decode). This is not a bridge-side error. Inspect the message for the underlying cause.".into(),
            ),
            suggested_next_tool: None,
            message: format!("Transport error: {cause}"),
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Preserve the original message format so existing CLI output and
        // tests that check error strings keep working.
        f.write_str(&self.message)
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(s: &str) -> BridgeErrorCode {
        BridgeError::from_bridge_message(s).code
    }

    #[test]
    fn no_program_loaded_variants() {
        assert_eq!(classify("No program loaded"), BridgeErrorCode::NoProgramLoaded);
        assert_eq!(classify("No program currently loaded"), BridgeErrorCode::NoProgramLoaded);
        assert_eq!(
            classify("No program loaded. Use 'open_program' or 'import' first."),
            BridgeErrorCode::NoProgramLoaded,
        );
    }

    #[test]
    fn classifies_named_misses() {
        assert_eq!(classify("Program not found: foo"), BridgeErrorCode::ProgramNotFound);
        assert_eq!(classify("Function not found"), BridgeErrorCode::FunctionNotFound);
        assert_eq!(classify("Invalid function target: bar"), BridgeErrorCode::FunctionNotFound);
        assert_eq!(classify("Symbol not found: baz"), BridgeErrorCode::SymbolNotFound);
        assert_eq!(classify("Type not found: my_struct"), BridgeErrorCode::TypeNotFound);
    }

    #[test]
    fn address_and_invalid_args() {
        assert_eq!(classify("Invalid address: not_hex"), BridgeErrorCode::AddressInvalid);
        assert_eq!(classify("Invalid signature 'void foo('"), BridgeErrorCode::InvalidArgs);
        assert_eq!(classify("Invalid comment type: weird"), BridgeErrorCode::InvalidArgs);
        assert_eq!(classify("Address required"), BridgeErrorCode::InvalidArgs);
        assert_eq!(classify("Address and name required"), BridgeErrorCode::InvalidArgs);
    }

    #[test]
    fn write_path_and_unknown_command() {
        assert_eq!(classify("Failed to create symbol: blah"), BridgeErrorCode::WriteFailed);
        assert_eq!(classify("Failed to decompile FUN_00401000"), BridgeErrorCode::WriteFailed);
        assert_eq!(classify("Unknown command: yeet"), BridgeErrorCode::UnknownCommand);
    }

    #[test]
    fn unknown_pattern_falls_through() {
        let err = BridgeError::from_bridge_message("Some unforeseen explosion happened");
        assert_eq!(err.code, BridgeErrorCode::Unknown);
        assert!(!err.recoverable);
    }

    #[test]
    fn recoverability_defaults() {
        let recoverable_msg = "No program loaded";
        let not_recoverable_msg = "Unknown command: yeet";
        assert!(BridgeError::from_bridge_message(recoverable_msg).recoverable);
        assert!(!BridgeError::from_bridge_message(not_recoverable_msg).recoverable);
    }

    #[test]
    fn display_preserves_original_message() {
        let raw = "Failed to create symbol: address occupied";
        let err = BridgeError::from_bridge_message(raw);
        assert_eq!(format!("{err}"), raw);
    }

    #[test]
    fn serializes_with_snake_case_code() {
        let err = BridgeError::from_bridge_message("No program loaded");
        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["code"], "no_program_loaded");
        assert_eq!(json["recoverable"], true);
        assert!(json["hint"].is_string());
        assert_eq!(json["suggested_next_tool"], "list_programs");
    }

    #[test]
    fn unreachable_and_timeout_constructors() {
        let u = BridgeError::unreachable(12345, "connection refused");
        assert_eq!(u.code, BridgeErrorCode::BridgeUnreachable);
        assert!(u.message.contains("12345"));
        assert!(u.message.contains("connection refused"));

        let t = BridgeError::timeout(300);
        assert_eq!(t.code, BridgeErrorCode::BridgeTimeout);
        assert!(t.recoverable);
    }
}
