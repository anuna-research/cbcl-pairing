//! SPEC-080 CON-001 / TEST-004: the account-selection object language.

use cbcl_pairing::credential_v2::{
    account_select_intent_digest, decode_object, CredentialV2AccountSelect, CredentialV2Error,
    CredentialV2Kind, CredentialV2Object, ACCOUNT_SELECT_DOMAIN, CONTROL_PADDING_BYTES,
};
use ciborium::Value;

const CEREMONY: [u8; 32] = [0x21; 32];
const APPLICATION: &str = "https://chat.anuna.io/selfsame/v2";
const SCOPE: [u8; 32] = [0x32; 32];

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../vectors/credential-v2-account-select.json")).unwrap()
}

#[test]
fn kind_eleven_is_the_control_arm_selection() {
    assert_eq!(CredentialV2Kind::AccountSelect.number(), 11);
    assert_eq!(CredentialV2Kind::ALL.len(), 12);
    assert_eq!(CredentialV2Kind::ALL[11], CredentialV2Kind::AccountSelect);
    assert!(!CredentialV2Kind::AccountSelect.is_large());
    assert_eq!(ACCOUNT_SELECT_DOMAIN.len(), 26);
}

#[test]
fn encodings_match_the_checked_in_vectors_and_round_trip() {
    let vectors = vectors();
    assert_eq!(
        vectors["intent_digest_hex"].as_str().unwrap(),
        hex::encode(account_select_intent_digest())
    );
    for (name, scope) in [("none", None), ("scope", Some(SCOPE))] {
        let selection = CredentialV2AccountSelect::new(CEREMONY, APPLICATION, scope).unwrap();
        let body = selection.encode();
        assert_eq!(
            vectors[name]["body_hex"].as_str().unwrap(),
            hex::encode(&body)
        );
        assert_eq!(CredentialV2AccountSelect::decode(&body).unwrap(), selection);
        let object = selection.object().unwrap();
        assert_eq!(object.kind(), CredentialV2Kind::AccountSelect);
        assert_eq!(object.padding_len(), CONTROL_PADDING_BYTES);
        assert_eq!(
            vectors[name]["content_hash_hex"].as_str().unwrap(),
            hex::encode(object.content_hash())
        );
        let decoded = decode_object(object.as_bytes()).unwrap();
        assert_eq!(
            CredentialV2AccountSelect::recognise(&decoded, &CEREMONY, APPLICATION).unwrap(),
            selection
        );
    }
}

fn body(members: Vec<Value>) -> Vec<u8> {
    cbor2::to_canonical_vec(&Value::Array(members)).unwrap()
}

fn members(selection: Value) -> Vec<Value> {
    vec![
        Value::Text(ACCOUNT_SELECT_DOMAIN.into()),
        Value::Bytes(CEREMONY.to_vec()),
        Value::Text(APPLICATION.into()),
        selection,
    ]
}

#[test]
fn every_shape_outside_the_grammar_refuses() {
    let good = members(Value::Array(vec![Value::Integer(0.into())]));
    assert!(CredentialV2AccountSelect::decode(&body(good.clone())).is_ok());

    let mut wrong_domain = good.clone();
    wrong_domain[0] = Value::Text("selfsame-account-select/v2".into());
    let mut three = good.clone();
    three.pop();
    let mut five = good.clone();
    five.push(Value::Integer(0.into()));
    let mut short_ceremony = good.clone();
    short_ceremony[1] = Value::Bytes(vec![0x21; 31]);
    let mut empty_application = good.clone();
    empty_application[2] = Value::Text(String::new());
    let mut long_application = good.clone();
    long_application[2] = Value::Text("a".repeat(2_049));
    let mut numeric_application = good.clone();
    numeric_application[2] = Value::Integer(7.into());
    let cases: Vec<(&str, Vec<Value>)> = vec![
        ("wrong domain", wrong_domain),
        ("three members", three),
        ("five members", five),
        ("31-octet ceremony", short_ceremony),
        ("empty application", empty_application),
        ("2049-char application", long_application),
        ("numeric application", numeric_application),
        (
            "tag 2",
            members(Value::Array(vec![Value::Integer(2.into())])),
        ),
        (
            "tag 1 without scope",
            members(Value::Array(vec![Value::Integer(1.into())])),
        ),
        (
            "tag 0 with scope",
            members(Value::Array(vec![
                Value::Integer(0.into()),
                Value::Bytes(SCOPE.to_vec()),
            ])),
        ),
        (
            "31-octet scope",
            members(Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(vec![0x32; 31]),
            ])),
        ),
        (
            "33-octet scope",
            members(Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(vec![0x32; 33]),
            ])),
        ),
        (
            "nested selection",
            members(Value::Array(vec![Value::Array(vec![Value::Integer(
                0.into(),
            )])])),
        ),
        (
            "map selection",
            members(Value::Map(vec![(
                Value::Integer(0.into()),
                Value::Integer(0.into()),
            )])),
        ),
    ];
    for (name, members) in cases {
        assert_eq!(
            CredentialV2AccountSelect::decode(&body(members)),
            Err(CredentialV2Error::Schema),
            "{name}"
        );
    }

    let canonical = body(good);
    let mut trailing = canonical.clone();
    trailing.push(0x00);
    assert_eq!(
        CredentialV2AccountSelect::decode(&trailing),
        Err(CredentialV2Error::TrailingBytes)
    );
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&canonical[1..]);
    indefinite.push(0xff);
    assert!(matches!(
        CredentialV2AccountSelect::decode(&indefinite),
        Err(CredentialV2Error::NonDeterministic | CredentialV2Error::MalformedCbor)
    ));
    assert_eq!(
        CredentialV2AccountSelect::decode(&[]),
        Err(CredentialV2Error::MalformedCbor)
    );
    assert_eq!(
        CredentialV2AccountSelect::new(CEREMONY, "", None),
        Err(CredentialV2Error::Schema)
    );
    assert_eq!(
        CredentialV2AccountSelect::new(CEREMONY, &"a".repeat(2_049), None),
        Err(CredentialV2Error::Schema)
    );
}

#[test]
fn recognition_binds_kind_digest_ceremony_and_application() {
    let selection = CredentialV2AccountSelect::new(CEREMONY, APPLICATION, Some(SCOPE)).unwrap();
    let object = selection.object().unwrap();
    assert_eq!(
        CredentialV2AccountSelect::recognise(&object, &[0x77; 32], APPLICATION),
        Err(CredentialV2Error::Profile)
    );
    assert_eq!(
        CredentialV2AccountSelect::recognise(&object, &CEREMONY, "https://other.example/app"),
        Err(CredentialV2Error::Profile)
    );
    let other_kind = CredentialV2Object::new(
        CredentialV2Kind::Refusal,
        account_select_intent_digest(),
        selection.encode(),
    )
    .unwrap();
    assert_eq!(
        CredentialV2AccountSelect::recognise(&other_kind, &CEREMONY, APPLICATION),
        Err(CredentialV2Error::Schema)
    );
    let other_digest =
        CredentialV2Object::new(CredentialV2Kind::AccountSelect, [0; 32], selection.encode())
            .unwrap();
    assert_eq!(
        CredentialV2AccountSelect::recognise(&other_digest, &CEREMONY, APPLICATION),
        Err(CredentialV2Error::Schema)
    );
}

#[test]
#[ignore = "prints the vector values for vectors/credential-v2-account-select.json"]
fn print_vectors() {
    println!(
        "intent_digest_hex {}",
        hex::encode(account_select_intent_digest())
    );
    for (name, scope) in [("none", None), ("scope", Some(SCOPE))] {
        let selection = CredentialV2AccountSelect::new(CEREMONY, APPLICATION, scope).unwrap();
        println!("{name} body_hex {}", hex::encode(selection.encode()));
        println!(
            "{name} content_hash_hex {}",
            hex::encode(selection.object().unwrap().content_hash())
        );
    }
}
