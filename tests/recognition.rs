//! SPEC-072 TEST-005 complete-recognition Red Gate.

use cbcl_pairing::wire::{
    decode_application_payload, decode_channel_frame, decode_client_message, decode_invitation,
    decode_pairing_decision, decode_pairing_intent, decode_sealed_plaintext, decode_server_message,
    RecognitionError,
};
use ciborium::Value;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(length: usize, fill: u8) -> Value {
    Value::Bytes(vec![fill; length])
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

fn encode(value: &Value) -> Vec<u8> {
    cbor2::to_canonical_vec(value).expect("test value encodes")
}

fn encode_permissive(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).expect("test value encodes permissively");
    encoded
}

fn direct_locator() -> Value {
    Value::Array(vec![uint(0), bytes(32, 0x11)])
}

fn valid_invitation() -> Value {
    map(vec![
        ("version", uint(1)),
        ("suite", text("CPACE25519-SHA512-D21")),
        ("application", text("anuna.io/agent/v1")),
        ("relay-origin", text("wss://relay.example")),
        ("locator", direct_locator()),
        ("secret", bytes(16, 0x22)),
    ])
}

fn valid_client_messages() -> Vec<Value> {
    vec![
        map(vec![("type", text("bind")), ("version", uint(1))]),
        map(vec![
            ("type", text("allocate")),
            ("locator-mode", uint(1)),
            ("ttl-seconds", uint(600)),
        ]),
        map(vec![("type", text("claim")), ("locator", direct_locator())]),
        map(vec![
            ("type", text("open")),
            ("mailbox-id", bytes(32, 1)),
            ("membership-token", bytes(32, 2)),
        ]),
        map(vec![
            ("type", text("put")),
            ("seq", uint(0)),
            ("body", bytes(1, 3)),
        ]),
        map(vec![("type", text("ack")), ("peer-seq", uint(0))]),
        map(vec![("type", text("close"))]),
        map(vec![("type", text("ping"))]),
    ]
}

#[test]
fn test_005_accepts_every_valid_client_command() {
    for message in valid_client_messages() {
        assert!(decode_client_message(&encode(&message)).is_ok());
    }
}

#[test]
fn test_005_rejects_unknown_and_duplicate_keys_for_every_client_command() {
    for message in valid_client_messages() {
        let Value::Map(entries) = message else {
            unreachable!()
        };

        let mut with_unknown = entries.clone();
        with_unknown.push((text("unknown"), uint(0)));
        assert!(decode_client_message(&encode(&Value::Map(with_unknown))).is_err());

        let type_entry = entries
            .iter()
            .find(|(key, _)| key == &text("type"))
            .expect("type entry")
            .clone();
        let mut with_duplicate = entries;
        with_duplicate.push(type_entry);
        assert!(decode_client_message(&encode_permissive(&Value::Map(with_duplicate))).is_err());
    }
}

#[test]
fn test_005_rejects_non_deterministic_and_trailing_cbor() {
    let mut non_deterministic = encode(&map(vec![("type", text("bind")), ("version", uint(1))]));
    let final_byte = non_deterministic.pop().expect("encoded version");
    assert_eq!(final_byte, 1);
    non_deterministic.extend_from_slice(&[0x18, 0x01]);
    assert_eq!(
        decode_client_message(&non_deterministic),
        Err(RecognitionError::NonDeterministic)
    );

    let mut trailing = encode(&valid_invitation());
    trailing.push(0);
    assert_eq!(
        decode_invitation(&trailing),
        Err(RecognitionError::TrailingBytes)
    );
}

#[test]
fn test_005_rejects_numeric_and_body_boundaries() {
    let frame_16 = map(vec![
        ("type", text("put")),
        ("seq", uint(16)),
        ("body", bytes(1, 3)),
    ]);
    assert!(decode_client_message(&encode(&frame_16)).is_err());

    let body_69633 = map(vec![
        ("type", text("put")),
        ("seq", uint(0)),
        ("body", bytes(69_633, 3)),
    ]);
    assert!(decode_client_message(&encode(&body_69633)).is_err());

    let lifetime_601 = map(vec![
        ("type", text("allocate")),
        ("locator-mode", uint(1)),
        ("ttl-seconds", uint(601)),
    ]);
    assert!(decode_client_message(&encode(&lifetime_601)).is_err());
}

#[test]
fn test_005_recognises_invitation_abnf_and_canonical_origin() {
    assert!(decode_invitation(&encode(&valid_invitation())).is_ok());

    for bad_application in [
        "anuna/agent/v1",
        "anuna.io//v1",
        "anuna.io/agent/v100",
        "-anuna.io/agent/v1",
        "anuna.io/agent_/v1",
    ] {
        let Value::Map(mut entries) = valid_invitation() else {
            unreachable!()
        };
        entries
            .iter_mut()
            .find(|(key, _)| key == &text("application"))
            .expect("application")
            .1 = text(bad_application);
        assert!(decode_invitation(&encode(&Value::Map(entries))).is_err());
    }

    for bad_origin in [
        "https://Relay.Example",
        "http://relay.example",
        "wss://user@relay.example",
        "wss://relay.example/path",
        "wss://relay.example/#fragment",
    ] {
        let Value::Map(mut entries) = valid_invitation() else {
            unreachable!()
        };
        entries
            .iter_mut()
            .find(|(key, _)| key == &text("relay-origin"))
            .expect("relay origin")
            .1 = text(bad_origin);
        assert!(decode_invitation(&encode(&Value::Map(entries))).is_err());
    }
}

#[test]
fn test_005_recognises_all_other_top_level_grammars() {
    let server = map(vec![("type", text("welcome")), ("version", uint(1))]);
    assert!(decode_server_message(&encode(&server)).is_ok());

    let channel = map(vec![
        ("v", uint(1)),
        ("kind", text("cpace")),
        ("role", uint(0)),
        ("control", bytes(1, 1)),
        ("message", bytes(1, 2)),
    ]);
    assert!(decode_channel_frame(&encode(&channel)).is_ok());

    let plaintext = map(vec![("control", bytes(1, 1))]);
    assert!(decode_sealed_plaintext(&encode(&plaintext)).is_ok());

    let intent = map(vec![
        ("type", text("intent")),
        ("application", text("anuna.io/agent/v1")),
        ("action", text("pair")),
        ("allocator-claim", bytes(1, 1)),
        ("claimant-claim", bytes(1, 2)),
        ("authority-summary", text("Pair one agent")),
        ("intent-nonce", bytes(32, 3)),
    ]);
    assert!(decode_pairing_intent(&encode(&intent)).is_ok());

    let decision = map(vec![
        ("type", text("decision")),
        ("intent-digest", bytes(32, 4)),
        ("decision", text("approve")),
    ]);
    assert!(decode_pairing_decision(&encode(&decision)).is_ok());

    let payload = map(vec![
        ("type", text("payload")),
        ("intent-digest", bytes(32, 4)),
        ("payload-type", text("example/v1")),
        ("body", bytes(1, 5)),
    ]);
    assert!(decode_application_payload(&encode(&payload)).is_ok());
}
