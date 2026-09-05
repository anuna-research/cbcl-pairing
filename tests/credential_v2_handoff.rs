//! SPEC-001 REQ-031; SPEC-077 CON-001, TEST-001 and TEST-006.
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::{
    credential_v2::{
        decode_carrier, encode_carrier, CredentialV2Carrier, CredentialV2CarrierInput,
        CredentialV2Handoff, CredentialV2HandoffError as Error, CredentialV2PresenceCode,
    },
    wire::{claim_commitment, ClaimToken},
};
use ciborium::Value;
use sha2::{Digest, Sha256};

const DOMAIN: &str = "selfsame-pairing-handoff/v1";
const C: [u8; 16] = [0x13; 16];
const T: [u8; 16] = [0x24; 16];

fn carrier_input() -> CredentialV2CarrierInput {
    CredentialV2CarrierInput {
        application_context: "https://a.b/a".into(),
        relay_origin: "https://r".into(),
        mailbox_id: [0x35; 32],
        carrier_ceremony_id: [0x46; 32],
        carrier_nonce: [0x57; 32],
        claim_commitment: claim_commitment([0x35; 32], &ClaimToken::new(T)),
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: None,
    }
}

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(carrier_input()).unwrap()
}

fn fields(public: Vec<u8>, c: Vec<u8>, t: Vec<u8>) -> Vec<Value> {
    vec![
        Value::Text(DOMAIN.into()),
        Value::Bytes(public),
        Value::Bytes(c),
        Value::Bytes(t),
    ]
}

fn text(bytes: &[u8]) -> String {
    format!("SSPAIR1:{}", Base64UrlUnpadded::encode_string(bytes))
}

fn outer(values: Vec<Value>) -> Vec<u8> {
    cbor2::to_canonical_vec(&Value::Array(values)).unwrap()
}

fn valid_bytes() -> Vec<u8> {
    outer(fields(
        encode_carrier(&carrier()).unwrap(),
        C.to_vec(),
        T.to_vec(),
    ))
}

fn refuses(input: &str, expected: Error) {
    let error = input.parse::<CredentialV2Handoff>().unwrap_err();
    assert_eq!(error, expected);
    assert_eq!(format!("{error}"), format!("{expected:?}"));
    assert!(std::error::Error::source(&error).is_none());
}

fn assert_roundtrip(carrier: CredentialV2Carrier, c: [u8; 16], t: [u8; 16]) {
    let public = encode_carrier(&carrier).unwrap();
    let digest = carrier.digest();
    let handoff =
        CredentialV2Handoff::new(carrier.clone(), CredentialV2PresenceCode::new(c, t)).unwrap();
    assert_eq!(format!("{handoff:?}"), "CredentialV2Handoff([REDACTED])");
    assert_eq!(format!("{handoff:#?}"), "CredentialV2Handoff([REDACTED])");
    assert_eq!(handoff.carrier(), &carrier);
    let encoded: zeroize::Zeroizing<String> = handoff.encode().unwrap();
    assert!(encoded.len() <= 3691);
    assert_eq!(*encoded, *handoff.encode().unwrap());
    let parsed: CredentialV2Handoff = encoded.parse().unwrap();
    assert_eq!(*parsed.encode().unwrap(), *encoded);
    let (recovered, presence) = parsed.into_parts();
    assert_eq!(encode_carrier(&recovered).unwrap(), public);
    assert_eq!(recovered.digest(), digest);
    assert_eq!(digest.as_slice(), Sha256::digest(&public).as_slice());
    let mut presence = presence.into_presence();
    assert_eq!(presence.cpace_secret(), &c);
    assert_eq!(presence.take_claim_token().unwrap().as_bytes(), &t);
    let (original, presence) = handoff.into_parts();
    assert_eq!(original, recovered);
    assert_eq!(presence.into_presence().cpace_secret(), &c);
}

#[test]
fn deterministic_vectors_preserve_exact_carrier_digest_and_independent_secrets() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/credential-v2-handoff.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let public = hex::decode(vector["carrier_hex"].as_str().unwrap()).unwrap();
        let c: [u8; 16] = hex::decode(vector["c_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let t: [u8; 16] = hex::decode(vector["t_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let carrier = decode_carrier(&public).unwrap();
        assert_eq!(hex::encode(carrier.digest()), vector["carrier_sha256"]);
        let expected = vector["handoff"].as_str().unwrap();
        let handoff =
            CredentialV2Handoff::new(carrier.clone(), CredentialV2PresenceCode::new(c, t)).unwrap();
        assert_eq!(*handoff.encode().unwrap(), expected);
        let parsed: CredentialV2Handoff = expected.parse().unwrap();
        assert_eq!(encode_carrier(parsed.carrier()).unwrap(), public);
        let decoded = Base64UrlUnpadded::decode_vec(&expected[8..]).unwrap();
        assert_eq!(hex::encode(&decoded), vector["decoded_hex"]);
        if vector["name"] == "maximum" {
            assert_eq!(
                (public.len(), decoded.len(), expected.len()),
                (2695, 2762, 3691)
            );
        }
        assert_roundtrip(carrier, c, t);
    }
}

// Deterministic domain generation follows the repo's assurance_properties harness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }
}

#[test]
fn valid_domain_properties_include_length_integer_key_and_secret_boundaries() {
    let mut rng = Rng(0x0770_0001_cafe_f00d);
    let expiries = [
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u32::MAX as u64,
        u32::MAX as u64 + 1,
        u64::MAX,
    ];
    for index in 0..2048 {
        let mut input = carrier_input();
        let app_len = if index == 0 {
            2048
        } else {
            13 + rng.next() as usize % 2036
        };
        let relay_len = if index == 0 {
            272
        } else {
            9 + rng.next() as usize % 264
        };
        input.application_context = format!("https://a.b/{}", "x".repeat(app_len - 12));
        input.relay_origin = format!("https://{}", "r".repeat(relay_len - 8));
        input.mailbox_id = rng.bytes();
        input.carrier_ceremony_id = rng.bytes();
        input.carrier_nonce = rng.bytes();
        input.relay_expires_at = if index == 0 {
            u64::MAX
        } else if index < 20 {
            expiries[index % 10]
        } else {
            rng.next()
        };
        input.expected_allocator_key = (index % 2 == 0).then(|| rng.bytes());
        let (c, t) = match index {
            0 => ([0; 16], [255; 16]),
            1 => ([255; 16], [0; 16]),
            2 => ([0; 16], [0; 16]), // Independence does not prohibit equality.
            _ => (rng.bytes(), rng.bytes()),
        };
        input.claim_commitment = claim_commitment(input.mailbox_id, &ClaimToken::new(t));
        let carrier = CredentialV2Carrier::new(input).unwrap();
        if index == 0 {
            assert_eq!(encode_carrier(&carrier).unwrap().len(), 2695);
        }
        assert_roundtrip(carrier, c, t);
    }
}

#[test]
fn commitment_guard_rejects_wrong_t_in_constructor() {
    for bit in 0..128 {
        let mut wrong = T;
        wrong[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            CredentialV2Handoff::new(carrier(), CredentialV2PresenceCode::new(C, wrong))
                .unwrap_err(),
            Error::Commitment
        );
    }
    let mut wrong_mailbox = carrier_input();
    wrong_mailbox.mailbox_id[0] ^= 1;
    assert_eq!(
        CredentialV2Handoff::new(
            CredentialV2Carrier::new(wrong_mailbox).unwrap(),
            CredentialV2PresenceCode::new(C, T)
        )
        .unwrap_err(),
        Error::Commitment
    );
}

#[test]
fn commitment_guard_rejects_wrong_t_in_recognizer() {
    let public = encode_carrier(&carrier()).unwrap();
    for bit in 0..128 {
        let mut wrong = T;
        wrong[bit / 8] ^= 1 << (bit % 8);
        refuses(
            &text(&outer(fields(public.clone(), C.to_vec(), wrong.to_vec()))),
            Error::Commitment,
        );
    }
}

#[test]
fn commitment_is_to_m_and_t_only_and_never_c_concatenated_with_t() {
    assert_roundtrip(carrier(), [0; 16], T);
    assert_roundtrip(carrier(), [255; 16], T);
    let mut wrong = carrier_input();
    let mut digest = Sha256::new();
    digest.update(b"cbcl-pairing claim-v2 commitment\0");
    digest.update(wrong.mailbox_id);
    digest.update(C);
    digest.update(T);
    wrong.claim_commitment = digest.finalize().into();
    let wrong = CredentialV2Carrier::new(wrong).unwrap();
    refuses(
        &text(&outer(fields(
            encode_carrier(&wrong).unwrap(),
            C.to_vec(),
            T.to_vec(),
        ))),
        Error::Commitment,
    );
}

#[test]
fn lexical_version_size_and_encoding_failures_are_closed() {
    let valid = text(&valid_bytes());
    for prefix in [
        "",
        "SSPAIR2:",
        "sspair1:",
        "SSPair1:",
        "PAIR1-",
        " SSPAIR1:",
    ] {
        refuses(&format!("{prefix}{}", &valid[8..]), Error::Version);
    }
    refuses(&"x".repeat(3692), Error::Oversize);
    refuses(&format!("SSPAIR1:{}", "A".repeat(3684)), Error::Oversize);
    for suffix in [
        "", "A", "AA=", "AA==", "AB", "AAB", "+AAA", "/AAA", "AA\n", " AA", "é", "AA\t",
    ] {
        refuses(&format!("SSPAIR1:{suffix}"), Error::Encoding);
    }
    for suffix in [" ", "\n", "\t", "="] {
        refuses(&format!("{valid}{suffix}"), Error::Encoding);
    }
    // Change only unused base64 bits on a complete otherwise valid handoff.
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/credential-v2-handoff.json")).unwrap();
    let mut maximum = vectors[1]["handoff"].as_str().unwrap().as_bytes().to_vec();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = maximum.last_mut().unwrap();
    let symbol = alphabet.iter().position(|v| v == last).unwrap();
    assert_eq!(symbol & 3, 0);
    *last = alphabet[symbol | 1];
    refuses(std::str::from_utf8(&maximum).unwrap(), Error::Encoding);
}

#[test]
fn fixed_schema_rejects_noncanonical_nested_extra_and_truncated_input() {
    let valid = valid_bytes();
    let public = encode_carrier(&carrier()).unwrap();
    for length in 0..valid.len() {
        refuses(
            &text(&valid[..length]),
            if length == 0 {
                Error::Encoding
            } else {
                Error::Schema
            },
        );
    }
    let mut bad = valid.clone();
    bad.push(0);
    refuses(&text(&bad), Error::Schema);
    let mut bad = vec![0x98, 4];
    bad.extend_from_slice(&valid[1..]);
    refuses(&text(&bad), Error::Schema);
    let mut bad = valid.clone();
    bad[0] = 0x9f;
    bad.push(0xff);
    refuses(&text(&bad), Error::Schema);
    let mut bad = vec![0x84, 0x79, 0, 27];
    bad.extend_from_slice(&valid[3..]);
    refuses(&text(&bad), Error::Schema);
    let mut bad = valid.clone();
    bad[1] = 0x58;
    refuses(&text(&bad), Error::Schema);
    // Nonminimal bstr lengths for the public carrier and each secret.
    let mut bad = valid[..30].to_vec();
    bad.extend_from_slice(&[0x5a, 0, 0]);
    bad.extend_from_slice(&valid[31..]);
    refuses(&text(&bad), Error::Schema);
    for offset in [valid.len() - 34, valid.len() - 17] {
        assert_eq!(valid[offset], 0x50);
        let mut bad = valid[..offset].to_vec();
        bad.extend_from_slice(&[0x58, 16]);
        bad.extend_from_slice(&valid[offset + 1..]);
        refuses(&text(&bad), Error::Schema);
    }
    let mut values = fields(public.clone(), C.to_vec(), T.to_vec());
    values[0] = Value::Text("selfsame-pairing-handoff/v2".into());
    refuses(&text(&outer(values)), Error::Version);
    for length in [0, 15, 17, 32] {
        refuses(
            &text(&outer(fields(public.clone(), vec![0; length], T.to_vec()))),
            Error::Schema,
        );
        refuses(
            &text(&outer(fields(public.clone(), C.to_vec(), vec![0; length]))),
            Error::Schema,
        );
    }
    for member in 0..4 {
        let mut values = fields(public.clone(), C.to_vec(), T.to_vec());
        values[member] = Value::Array(vec![Value::Array(vec![])]);
        refuses(&text(&outer(values)), Error::Schema);
    }
    let mut values = fields(public, C.to_vec(), T.to_vec());
    values.push(Value::Null);
    refuses(&text(&outer(values)), Error::Schema);
    refuses(&text(&vec![0x81; 2762]), Error::Schema);
    refuses(
        &text(&outer(fields(vec![], C.to_vec(), T.to_vec()))),
        Error::Schema,
    );
    // A giant advertised bstr length never allocates that amount.
    let mut bad = valid[..30].to_vec();
    bad.extend_from_slice(&[0x5b, 255, 255, 255, 255, 255, 255, 255, 255]);
    refuses(&text(&bad), Error::Schema);
}

#[test]
fn inner_carrier_errors_are_redacted_and_use_the_existing_recognizer() {
    for public in [vec![0xa0], vec![0xff], vec![0x81; 2000]] {
        refuses(
            &text(&outer(fields(public, C.to_vec(), T.to_vec()))),
            Error::Carrier,
        );
    }
    let public = encode_carrier(&carrier()).unwrap();
    let mut noncanonical = vec![0xb8, 10];
    noncanonical.extend_from_slice(&public[1..]);
    refuses(
        &text(&outer(fields(noncanonical, C.to_vec(), T.to_vec()))),
        Error::Carrier,
    );
}
