//! Property-based round-trip tests for the bridge IPC protocol.
//!
//! The core property exercised here is:
//!
//!     value -> serialize -> deserialize -> equal_value
//!
//! `BridgeRequest` only derives `Serialize` and `BridgeResponse` only derives
//! `Deserialize`, neither implements `PartialEq`. To round-trip without
//! modifying the protocol types, we compare canonical `serde_json::Value`
//! representations of inputs and outputs.
//!
//! Tracks beads issue ghidra-cli-b4g (E3.1).

use ghidra_cli::ipc::protocol::{BridgeRequest, BridgeResponse};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Command names on the wire are short ASCII identifiers ("ping",
/// "list_functions", "patch_bytes", ...). We allow underscores and digits
/// to match the real corpus, plus the empty string and unicode strings as
/// adversarial edge cases via a separate `any::<String>()` strategy.
fn command_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Realistic command names
        "[a-z][a-z0-9_]{0,31}",
        // Adversarial: arbitrary unicode strings (bounded length to keep
        // shrinking fast and avoid 10MB stress strings)
        ".{0,64}",
    ]
}

/// Strategy for arbitrary JSON values, recursively built. Mirrors what the
/// bridge actually transmits (numbers, strings, arrays, nested objects).
fn json_value_strategy() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        // u64 addresses (the bridge passes Ghidra addresses as numbers)
        any::<u64>().prop_map(|n| serde_json::Value::Number(n.into())),
        any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
        // A few representative finite floats. Arbitrary f64s round-trip
        // lossily through `serde_json`'s shortest-decimal formatter for
        // edge magnitudes, which is a serde_json quirk -- not a protocol
        // bug -- and the bridge never transmits floats in practice (Ghidra
        // addresses are u64s and numeric payloads are integers). We keep
        // a handful of small, round-trip-safe floats to ensure float
        // handling itself works.
        prop_oneof![
            Just(0.0_f64),
            Just(1.0_f64),
            Just(-1.0_f64),
            Just(0.5_f64),
            Just(2.75_f64),
            Just(-2.5_f64),
        ]
        .prop_filter_map("safe finite f64", |f| {
            serde_json::Number::from_f64(f).map(serde_json::Value::Number)
        }),
        ".{0,64}".prop_map(serde_json::Value::String),
    ];

    leaf.prop_recursive(
        4,  // max depth
        32, // max total nodes
        8,  // max items per collection
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::Array),
                prop::collection::hash_map(".{0,16}", inner, 0..8).prop_map(|m| {
                    let mut obj = serde_json::Map::new();
                    for (k, v) in m {
                        obj.insert(k, v);
                    }
                    serde_json::Value::Object(obj)
                }),
            ]
        },
    )
}

/// Strategy for `BridgeRequest`: a command name and an optional args payload.
fn bridge_request_strategy() -> impl Strategy<Value = BridgeRequest> {
    (
        command_name_strategy(),
        prop::option::of(json_value_strategy()),
    )
        .prop_map(|(command, args)| BridgeRequest { command, args })
}

/// Status values produced by the Java bridge in the wild.
fn status_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("success".to_string()),
        Just("error".to_string()),
        Just("shutdown".to_string()),
        // Adversarial: any other string still has to deserialize cleanly
        "[a-z]{1,16}".prop_map(String::from),
    ]
}

/// Strategy for the *wire form* of a `BridgeResponse`: a JSON object with
/// status/data/message fields. We generate the canonical JSON value (rather
/// than a `BridgeResponse` directly) because `BridgeResponse` doesn't derive
/// `Serialize`, so this is the natural way to feed the deserializer.
fn bridge_response_wire_strategy() -> impl Strategy<Value = serde_json::Value> {
    (
        status_strategy(),
        prop::option::of(json_value_strategy()),
        prop::option::of(".{0,128}".prop_map(String::from)),
    )
        .prop_map(|(status, data, message)| {
            let mut obj = serde_json::Map::new();
            obj.insert("status".into(), serde_json::Value::String(status));
            if let Some(d) = data {
                obj.insert("data".into(), d);
            } else {
                // Explicit null is one of the legal wire forms; the field is
                // optional (skip-serializing-if=Option::is_none on the Java
                // side, but Rust derives accept `null` either way).
                obj.insert("data".into(), serde_json::Value::Null);
            }
            if let Some(m) = message {
                obj.insert("message".into(), serde_json::Value::String(m));
            }
            serde_json::Value::Object(obj)
        })
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1024,
        // Deterministic seeding: proptest defaults to a fixed PRNG sequence
        // unless PROPTEST_SEED is set. We don't introduce any external
        // randomness, so CI runs are reproducible.
        .. ProptestConfig::default()
    })]

    /// Round-trip property for `BridgeRequest`.
    ///
    /// We serialize the generated request, parse the JSON back as a
    /// `serde_json::Value`, and reconstruct the canonical wire form from the
    /// original input. The two values must compare equal.
    ///
    /// This also enforces the documented `skip_serializing_if = Option::is_none`
    /// behavior on `args`: when args is `None`, the serialized form must NOT
    /// contain an `args` key.
    #[test]
    fn bridge_request_roundtrip(req in bridge_request_strategy()) {
        let serialized = serde_json::to_string(&req)
            .expect("BridgeRequest must serialize");

        let parsed: serde_json::Value = serde_json::from_str(&serialized)
            .expect("serialized BridgeRequest must be valid JSON");

        // Reconstruct expected wire form from the original input.
        let mut expected = serde_json::Map::new();
        expected.insert("command".into(), serde_json::Value::String(req.command.clone()));
        if let Some(args) = req.args.as_ref() {
            expected.insert("args".into(), args.clone());
        }
        let expected = serde_json::Value::Object(expected);

        prop_assert_eq!(&parsed, &expected);

        // Explicit check on the documented skip behavior.
        if req.args.is_none() {
            prop_assert!(
                !serialized.contains("\"args\""),
                "args=None must omit the field from the wire form, got: {}",
                serialized
            );
        }
    }

    /// Round-trip property for `BridgeResponse`.
    ///
    /// Direction: wire JSON -> `BridgeResponse` -> canonical JSON. The
    /// canonicalized output (status + optional data + optional message)
    /// must match the canonicalized input.
    #[test]
    fn bridge_response_roundtrip(wire in bridge_response_wire_strategy()) {
        let serialized = serde_json::to_string(&wire)
            .expect("wire JSON must serialize");

        let response: BridgeResponse = serde_json::from_str(&serialized)
            .expect("BridgeResponse must deserialize from valid wire JSON");

        // Reconstruct what the response represents semantically.
        let input_obj = wire.as_object().expect("wire form is an object");
        let input_status = input_obj
            .get("status")
            .and_then(|v| v.as_str())
            .expect("status is a string");
        prop_assert_eq!(&response.status, input_status);

        // `data`: the deserialized value should match the input field. Note
        // that `Option<Value>` deserializes a present `null` as `Some(Null)`,
        // not `None`, so we compare directly against the input value.
        let input_data = input_obj.get("data").cloned().unwrap_or(serde_json::Value::Null);
        let response_data = response.data.unwrap_or(serde_json::Value::Null);
        prop_assert_eq!(&response_data, &input_data);

        // `message`: optional string. Missing field => None; present string => Some.
        let input_message = input_obj.get("message").and_then(|v| v.as_str());
        prop_assert_eq!(response.message.as_deref(), input_message);
    }

    /// Single-line wire invariant: `BridgeRequest` serializes to a payload
    /// with no embedded newlines, because the bridge reads one line per
    /// request (see `src/ipc/README.md` Wire Format section).
    #[test]
    fn bridge_request_serializes_single_line(req in bridge_request_strategy()) {
        let serialized = serde_json::to_string(&req)
            .expect("BridgeRequest must serialize");
        prop_assert!(
            !serialized.contains('\n'),
            "serialized BridgeRequest must not contain newlines (one-line wire format), got: {:?}",
            serialized
        );
    }

    /// Double round-trip: deserialized response should re-serialize the
    /// same canonical structure (idempotence). This catches drift between
    /// serde defaults and the documented wire form.
    #[test]
    fn bridge_response_double_roundtrip(wire in bridge_response_wire_strategy()) {
        let s1 = serde_json::to_string(&wire).unwrap();
        let resp: BridgeResponse = serde_json::from_str(&s1).unwrap();

        // Rebuild canonical form from the deserialized response and compare.
        let mut rebuilt = serde_json::Map::new();
        rebuilt.insert("status".into(), serde_json::Value::String(resp.status.clone()));
        rebuilt.insert(
            "data".into(),
            resp.data.clone().unwrap_or(serde_json::Value::Null),
        );
        if let Some(m) = resp.message.as_ref() {
            rebuilt.insert("message".into(), serde_json::Value::String(m.clone()));
        }

        // Compare the same keys we put in the input.
        let input_obj = wire.as_object().unwrap();
        for (k, v) in input_obj.iter() {
            let r = rebuilt.get(k).unwrap_or(&serde_json::Value::Null);
            prop_assert_eq!(r, v, "field `{}` drifted across round trip", k);
        }
    }
}
