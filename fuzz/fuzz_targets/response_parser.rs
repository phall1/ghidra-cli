//! Fuzz target for the bridge response parser (E3.2 / ghidra-cli-2i2).
//!
//! The response parser is a security boundary: the bridge process is in-tree
//! but the wire format is a single line of JSON read from a TCP socket. A
//! corrupted bridge — or a hostile process that hijacked the loopback port —
//! could feed arbitrary bytes, so the parser must never panic, never go
//! quadratic, and never leak memory.
//!
//! Run locally:
//!   cargo +nightly fuzz run response_parser -- -max_total_time=60
//!
//! The CI gate (E3.2) runs the same command for a minute. Findings land in
//! fuzz/artifacts/response_parser/ and crash inputs in
//! fuzz/corpus/response_parser/.

#![no_main]

use ghidra_cli::ipc::protocol::BridgeResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Match what `BridgeClient::send_command` actually does: read one line
    // and try to deserialize it as a BridgeResponse. Non-UTF-8 inputs are
    // valid fuzz inputs — `serde_json::from_slice` rejects them as parse
    // errors, which is the behavior we want to assert is panic-free.
    let _ = serde_json::from_slice::<BridgeResponse>(data);

    // Also exercise the UTF-8 path explicitly — `BridgeClient` uses
    // `from_str` on a `String` produced by `BufReader::read_line`, so a
    // well-formed UTF-8 input is the more realistic adversarial shape.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<BridgeResponse>(s);
    }
});
