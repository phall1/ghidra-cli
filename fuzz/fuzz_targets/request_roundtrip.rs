//! Fuzz target for BridgeRequest serialization (E3.2 / ghidra-cli-2i2).
//!
//! Complements `response_parser` by exercising the serialize side. The wire
//! format must survive arbitrary command names + argument payloads without
//! panicking, even though in production we only emit a closed set of
//! commands. This catches future regressions if anyone wires a user-supplied
//! string straight into `BridgeRequest::command`.
//!
//! Run locally:
//!   cargo +nightly fuzz run request_roundtrip -- -max_total_time=60

#![no_main]

use ghidra_cli::ipc::protocol::BridgeRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split data into "command bytes" and "args JSON bytes" on a NUL boundary
    // so libfuzzer can reach both fields without us having to embed an Arbitrary
    // impl. NUL is rare in JSON, so most inputs end up as "command only".
    let (cmd_bytes, args_bytes) = match data.iter().position(|b| *b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };

    let Ok(cmd) = std::str::from_utf8(cmd_bytes) else {
        return;
    };

    let args = if args_bytes.is_empty() {
        None
    } else {
        // serde_json may reject the args bytes — that's fine; we only fuzz
        // the request serializer when args parses to a Value.
        serde_json::from_slice::<serde_json::Value>(args_bytes).ok()
    };

    let req = BridgeRequest {
        command: cmd.to_owned(),
        args,
    };

    let _ = serde_json::to_string(&req);
});
