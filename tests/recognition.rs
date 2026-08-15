//! SPEC-072 TEST-005 complete-recognition Red Gate.

use cbcl_pairing::wire::{
    decode_application_payload, decode_channel_frame, decode_client_message, decode_invitation,
    decode_pairing_decision, decode_pairing_intent, decode_sealed_plaintext, decode_server_message,
    encode_application_payload, encode_channel_frame, encode_client_message, encode_invitation,
    encode_pairing_decision, encode_pairing_intent, encode_sealed_plaintext, encode_server_message,
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

fn complete_invitation() -> Value {
    map(vec![
        ("version", uint(1)),
        ("suite", text("CPACE25519-SHA512-D21")),
        ("application", text("anuna.io/credential/v1")),
        ("relay-origin", text("https://relay.example:8443")),
        ("locator", Value::Array(vec![uint(1), uint(999_999_999)])),
        ("secret", bytes(64, 0x22)),
        ("expected-allocator-key", bytes(32, 0x33)),
        ("expected-claimant-key", bytes(32, 0x44)),
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

fn valid_server_messages() -> Vec<Value> {
    let mut messages = vec![
        map(vec![("type", text("welcome")), ("version", uint(1))]),
        map(vec![
            ("type", text("allocated")),
            ("mailbox-id", bytes(32, 1)),
            ("membership-token", bytes(32, 2)),
            ("expires-at", uint(u64::MAX)),
        ]),
        map(vec![
            ("type", text("allocated")),
            ("mailbox-id", bytes(32, 1)),
            ("membership-token", bytes(32, 2)),
            ("nameplate", uint(999_999_999)),
            ("expires-at", uint(1_800_000_000)),
        ]),
        map(vec![
            ("type", text("claimed")),
            ("mailbox-id", bytes(32, 1)),
            ("membership-token", bytes(32, 2)),
            ("expires-at", uint(1_800_000_000)),
        ]),
        map(vec![
            ("type", text("frame")),
            ("peer-seq", uint(15)),
            ("body", bytes(69_632, 3)),
        ]),
        map(vec![("type", text("acknowledged")), ("seq", uint(15))]),
        map(vec![("type", text("pong"))]),
    ];
    for reason in ["closed", "crowded", "expired", "conflict"] {
        messages.push(map(vec![
            ("type", text("closed")),
            ("reason", text(reason)),
        ]));
    }
    for code in [400, 404, 409, 410, 413, 429, 503] {
        messages.push(map(vec![("type", text("error")), ("code", uint(code))]));
    }
    messages
}

fn valid_channel_frames() -> Vec<Value> {
    vec![
        map(vec![
            ("v", uint(1)),
            ("kind", text("cpace")),
            ("role", uint(0)),
            ("control", bytes(1, 1)),
            ("message", bytes(65_536, 2)),
        ]),
        map(vec![
            ("v", uint(1)),
            ("kind", text("cpace")),
            ("role", uint(1)),
            ("control", bytes(2_048, 1)),
            ("message", bytes(1, 2)),
        ]),
        map(vec![
            ("v", uint(1)),
            ("kind", text("finished")),
            ("role", uint(0)),
            ("control", bytes(1, 1)),
            ("value", bytes(64, 2)),
        ]),
        map(vec![
            ("v", uint(1)),
            ("kind", text("finished")),
            ("role", uint(1)),
            ("control", bytes(1, 1)),
            ("value", bytes(64, 2)),
        ]),
        map(vec![
            ("v", uint(1)),
            ("kind", text("sealed")),
            ("direction", uint(0)),
            ("counter", uint(0)),
            ("ciphertext", bytes(17, 3)),
        ]),
        map(vec![
            ("v", uint(1)),
            ("kind", text("sealed")),
            ("direction", uint(1)),
            ("counter", uint(u64::MAX)),
            ("ciphertext", bytes(69_572, 3)),
        ]),
    ]
}

fn indefinite_map(value: &Value) -> Vec<u8> {
    let canonical = encode(value);
    assert!((0xa0..=0xb7).contains(&canonical[0]));
    let mut encoded = Vec::with_capacity(canonical.len() + 1);
    encoded.push(0xbf);
    encoded.extend_from_slice(&canonical[1..]);
    encoded.push(0xff);
    encoded
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
        assert_eq!(
            decode_client_message(&encode(&Value::Map(with_unknown))),
            Err(RecognitionError::Schema)
        );

        let type_entry = entries
            .iter()
            .find(|(key, _)| key == &text("type"))
            .expect("type entry")
            .clone();
        let mut with_duplicate = entries;
        with_duplicate.push(type_entry);
        assert_eq!(
            decode_client_message(&encode_permissive(&Value::Map(with_duplicate))),
            Err(RecognitionError::DuplicateKey)
        );
    }
}

#[test]
fn test_005_rejects_non_deterministic_and_trailing_cbor() {
    for message in valid_client_messages() {
        assert_eq!(
            decode_client_message(&indefinite_map(&message)),
            Err(RecognitionError::NonDeterministic)
        );

        let mut trailing = encode(&message);
        trailing.push(0);
        assert_eq!(
            decode_client_message(&trailing),
            Err(RecognitionError::TrailingBytes)
        );
    }

    assert_eq!(
        decode_client_message(&[0xff]),
        Err(RecognitionError::MalformedCbor)
    );
}

#[test]
fn test_005_rejects_numeric_and_body_boundaries() {
    let frame_16 = map(vec![
        ("type", text("put")),
        ("seq", uint(16)),
        ("body", bytes(1, 3)),
    ]);
    assert_eq!(
        decode_client_message(&encode(&frame_16)),
        Err(RecognitionError::Schema)
    );

    let body_69633 = map(vec![
        ("type", text("put")),
        ("seq", uint(0)),
        ("body", bytes(69_633, 3)),
    ]);
    assert_eq!(
        decode_client_message(&encode(&body_69633)),
        Err(RecognitionError::Schema)
    );

    let lifetime_601 = map(vec![
        ("type", text("allocate")),
        ("locator-mode", uint(1)),
        ("ttl-seconds", uint(601)),
    ]);
    assert_eq!(
        decode_client_message(&encode(&lifetime_601)),
        Err(RecognitionError::Schema)
    );
}

#[test]
fn test_005_recognises_invitation_abnf_and_canonical_origin() {
    assert!(decode_invitation(&encode(&valid_invitation())).is_ok());
    assert!(decode_invitation(&encode(&complete_invitation())).is_ok());

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
        assert_eq!(
            decode_invitation(&encode(&Value::Map(entries))),
            Err(RecognitionError::ApplicationId)
        );
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
        assert_eq!(
            decode_invitation(&encode(&Value::Map(entries))),
            Err(RecognitionError::RelayOrigin)
        );
    }
}

#[test]
fn test_005_recognises_all_other_top_level_grammars() {
    for server in valid_server_messages() {
        assert!(decode_server_message(&encode(&server)).is_ok());
    }
    for channel in valid_channel_frames() {
        assert!(decode_channel_frame(&encode(&channel)).is_ok());
    }
    for plaintext in [
        map(vec![("control", bytes(1, 1))]),
        map(vec![
            ("control", bytes(2_048, 1)),
            ("body", bytes(65_536, 2)),
        ]),
    ] {
        assert!(decode_sealed_plaintext(&encode(&plaintext)).is_ok());
    }

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

    for outcome in ["approve", "decline"] {
        let decision = map(vec![
            ("type", text("decision")),
            ("intent-digest", bytes(32, 4)),
            ("decision", text(outcome)),
        ]);
        assert!(decode_pairing_decision(&encode(&decision)).is_ok());
    }

    let payload = map(vec![
        ("type", text("payload")),
        ("intent-digest", bytes(32, 4)),
        ("payload-type", text("example/v1")),
        ("body", bytes(1, 5)),
    ]);
    assert!(decode_application_payload(&encode(&payload)).is_ok());
}

#[test]
fn test_005_all_typed_values_roundtrip_to_identical_deterministic_bytes() {
    for invitation in [valid_invitation(), complete_invitation()] {
        let canonical = encode(&invitation);
        let typed = decode_invitation(&canonical).expect("valid invitation");
        assert_eq!(
            encode_invitation(&typed).expect("encode invitation"),
            canonical
        );
    }

    for message in valid_client_messages() {
        let canonical = encode(&message);
        let typed = decode_client_message(&canonical).expect("valid client message");
        assert_eq!(
            encode_client_message(&typed).expect("encode client message"),
            canonical
        );
    }

    for message in valid_server_messages() {
        let canonical = encode(&message);
        let typed = decode_server_message(&canonical).expect("valid server message");
        assert_eq!(
            encode_server_message(&typed).expect("encode server message"),
            canonical
        );
    }

    for frame in valid_channel_frames() {
        let canonical = encode(&frame);
        let typed = decode_channel_frame(&canonical).expect("valid channel frame");
        assert_eq!(
            encode_channel_frame(&typed).expect("encode channel frame"),
            canonical
        );
    }

    let plaintext = map(vec![("control", bytes(1, 1)), ("body", bytes(1, 2))]);
    let canonical = encode(&plaintext);
    let typed = decode_sealed_plaintext(&canonical).expect("valid sealed plaintext");
    assert_eq!(
        encode_sealed_plaintext(&typed).expect("encode sealed plaintext"),
        canonical
    );

    let intent = map(vec![
        ("type", text("intent")),
        ("application", text("anuna.io/agent/v1")),
        ("action", text("pair")),
        ("allocator-claim", bytes(1, 1)),
        ("claimant-claim", bytes(1, 2)),
        ("authority-summary", text("Pair one agent")),
        ("intent-nonce", bytes(32, 3)),
    ]);
    let canonical = encode(&intent);
    let typed = decode_pairing_intent(&canonical).expect("valid intent");
    assert_eq!(
        encode_pairing_intent(&typed).expect("encode intent"),
        canonical
    );

    for outcome in ["approve", "decline"] {
        let decision = map(vec![
            ("type", text("decision")),
            ("intent-digest", bytes(32, 4)),
            ("decision", text(outcome)),
        ]);
        let canonical = encode(&decision);
        let typed = decode_pairing_decision(&canonical).expect("valid decision");
        assert_eq!(
            encode_pairing_decision(&typed).expect("encode decision"),
            canonical
        );
    }

    let payload = map(vec![
        ("type", text("payload")),
        ("intent-digest", bytes(32, 4)),
        ("payload-type", text("example/v1")),
        ("body", bytes(1, 5)),
    ]);
    let canonical = encode(&payload);
    let typed = decode_application_payload(&canonical).expect("valid payload");
    assert_eq!(
        encode_application_payload(&typed).expect("encode payload"),
        canonical
    );
}
