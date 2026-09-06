//! SPEC-078 REQ-001/002, TEST-001/002/006/007; SPEC-001 TEST-063/064/066.
use base64ct::{Base64UrlUnpadded, Encoding};
use bip39::Language;
use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, encode_carrier, encode_frame, CredentialV2Carrier,
        CredentialV2CarrierInput, CredentialV2Context, CredentialV2Frame, CredentialV2Handoff,
        CredentialV2ManualBootstrap as Bootstrap, CredentialV2ManualError as Error,
        CredentialV2ManualWords as Words, CredentialV2Presence, CredentialV2PresenceCode,
        PendingCredentialV2Channel,
    },
    wire::{claim_commitment, ClaimToken, Side},
};
use ciborium::Value;
use sha2::{Digest, Sha256};

const T: [u8; 16] = [0x24; 16];
const NOW: u64 = 1_800_000_000;
fn input() -> CredentialV2CarrierInput {
    CredentialV2CarrierInput {
        application_context: "https://a.b/a".into(),
        relay_origin: "https://r".into(),
        mailbox_id: [0x35; 32],
        carrier_ceremony_id: [0x46; 32],
        carrier_nonce: [0x57; 32],
        claim_commitment: claim_commitment([0x35; 32], &ClaimToken::new(T)),
        relay_expires_at: NOW + 900,
        expected_allocator_key: Some([0x68; 32]),
    }
}
fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(input()).unwrap()
}
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../vectors/credential-v2-manual.json")).unwrap()
}
fn bytes(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}
fn fields(public: Vec<u8>, t: Vec<u8>) -> Vec<Value> {
    vec![
        Value::Text("selfsame-pairing-manual/v1".into()),
        Value::Bytes(public),
        Value::Bytes(t),
    ]
}
fn text(raw: &[u8]) -> String {
    format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(raw))
}
fn outer(fields: Vec<Value>) -> Vec<u8> {
    cbor2::to_canonical_vec(&Value::Array(fields)).unwrap()
}
fn raw() -> Vec<u8> {
    outer(fields(encode_carrier(&carrier()).unwrap(), T.to_vec()))
}
fn refuses(s: &str, error: Error) {
    assert_eq!(Bootstrap::recognise(s, NOW).unwrap_err(), error);
    assert_eq!(format!("{error}"), format!("{error:?}"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn independent_word_vectors_pin_list_hash_indices_checksum_mapping_and_mask() {
    let vectors = vectors();
    let list = Language::English.word_list();
    assert_eq!(list.len(), 2048);
    assert!(list
        .iter()
        .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase())));
    let list_bytes = format!("{}\n", list.join("\n"));
    assert_eq!(
        hex::encode(Sha256::digest(list_bytes)),
        vectors["word_list_sha256"]
    );
    let mut branches = [false; 8];
    for v in vectors["words"].as_array().unwrap() {
        let n = v["n"].as_u64().unwrap() as u32;
        let checksum = v["checksum"].as_u64().unwrap() as usize;
        branches[checksum] = true;
        let expected = v["words"].as_str().unwrap();
        for high in [0, 1 << 30, 2 << 30, 3 << 30] {
            let words = Words::from_csprng((n | high).to_be_bytes());
            assert_eq!(*words.encode(), expected);
            assert_eq!(hex::encode(words.cpace_secret()), v["c_hex"]);
        }
        let parsed: Words = expected.parse().unwrap();
        assert_eq!(hex::encode(parsed.cpace_secret()), v["c_hex"]);
        assert_eq!(*parsed.encode(), expected);
        assert_eq!(format!("{parsed:?}"), "CredentialV2ManualWords([REDACTED])");
        let indices: Vec<usize> = expected
            .split(' ')
            .map(|word| list.binary_search(&word).unwrap())
            .collect();
        assert_eq!(serde_json::json!(indices), v["indices"]);
        // Every incorrect checksum uses complete valid list words, so the checksum guard is reached.
        let last = indices[2] & !7;
        for wrong in 0..8 {
            if wrong != checksum {
                let phrase = format!(
                    "{} {} {}",
                    list[indices[0]],
                    list[indices[1]],
                    list[last | wrong]
                );
                assert_eq!(phrase.parse::<Words>().unwrap_err(), Error::Checksum);
            }
        }
    }
    assert!(branches.into_iter().all(|b| b));
}

#[test]
fn independent_bootstrap_vectors_have_no_c_or_verifier_and_exact_bounds() {
    let vectors = vectors();
    for v in vectors["bootstraps"].as_array().unwrap() {
        let public = bytes(&v["carrier_hex"]);
        let raw = bytes(&v["decoded_hex"]);
        let expected = v["bootstrap"].as_str().unwrap();
        let carrier = decode_carrier(&public).unwrap();
        let t: [u8; 16] = bytes(&v["t_hex"]).try_into().unwrap();
        assert_eq!(hex::encode(carrier.digest()), v["carrier_sha256"]);
        assert_eq!(hex::encode(carrier.claim_commitment()), v["commitment_hex"]);
        let bootstrap = Bootstrap::new(carrier.clone(), t, 0).unwrap();
        assert_eq!(*bootstrap.encode().unwrap(), expected);
        assert_eq!(Base64UrlUnpadded::decode_vec(&expected[10..]).unwrap(), raw);
        assert_eq!(public.len() as u64, v["carrier_len"].as_u64().unwrap());
        assert_eq!(raw.len() as u64, v["decoded_len"].as_u64().unwrap());
        assert_eq!(expected.len() as u64, v["text_len"].as_u64().unwrap());
        if v["name"] == "maximum" {
            assert_eq!(
                (public.len(), raw.len(), expected.len()),
                (2695, 2744, 3669)
            );
        }
        assert_eq!(
            format!("{bootstrap:#?}"),
            "CredentialV2ManualBootstrap([REDACTED])"
        );
        let decoded: Value = ciborium::de::from_reader(raw.as_slice()).unwrap();
        assert_eq!(decoded, Value::Array(fields(public.clone(), t.to_vec())));
        // Same bootstrap accepts any independently checksum-valid phrase, no C verifier.
        for n in [0_u32, 1, 0x3fff_ffff] {
            let words = Words::from_csprng(n.to_be_bytes());
            let c = *words.cpace_secret();
            let (recovered, code) =
                Bootstrap::recognise_pair(expected, &words.encode(), 0).unwrap();
            assert_eq!(recovered, carrier);
            let mut presence = code.into_presence();
            assert_eq!(presence.cpace_secret(), &c);
            assert_eq!(presence.take_claim_token().unwrap().as_bytes(), &t);
        }
    }
}

#[test]
fn phrase_normalization_is_exactly_ascii_case_and_four_separators() {
    let canonical = Words::from_csprng([0x12, 0x34, 0x56, 0x78]).encode();
    let words: Vec<_> = canonical.split(' ').collect();
    for separator in [" ", "\t", "\r", "\n", " \t\r\n", "\r\n"] {
        for left in ["", "\t \r\n"] {
            for right in ["", "\n\r\t "] {
                let s = format!(
                    "{left}{}{separator}{}{separator}{}{right}",
                    words[0].to_ascii_uppercase(),
                    words[1],
                    words[2].to_ascii_uppercase()
                );
                assert_eq!(*s.parse::<Words>().unwrap().encode(), *canonical);
            }
        }
    }
    let bounded = format!("{}{}", " ".repeat(128 - canonical.len()), *canonical);
    assert_eq!(bounded.len(), 128);
    assert!(bounded.parse::<Words>().is_ok());
    assert_eq!(
        format!(" {bounded}").parse::<Words>().unwrap_err(),
        Error::Oversize
    );
    for s in [
        "",
        "abandon",
        "abandon abandon",
        "abandon abandon abandon abandon",
        "aband abandon abandon",
        "zzzzzzzz abandon abandon",
        "abandonabandon abandon",
        "abandon, abandon abandon",
        "abandon-abandon-abandon",
    ] {
        assert_eq!(s.parse::<Words>().unwrap_err(), Error::Schema, "{s}");
    }
    for separator in [
        "\u{b}", "\u{c}", "\0", ",", "-", "_", "/", "\u{a0}", "\u{2003}",
    ] {
        let s = words.join(separator);
        assert!(s.parse::<Words>().is_err());
    }
    for s in [
        "ábaco abandon abandon",
        "Ａbandon abandon abandon",
        "abandon abandon abandon😀",
    ] {
        assert_eq!(s.parse::<Words>().unwrap_err(), Error::Encoding);
    }
    // Every disallowed ASCII separator is tested; no split_ascii_whitespace widening.
    for b in 0_u8..=127 {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        let s = words.join(&char::from(b).to_string());
        assert!(s.parse::<Words>().is_err());
    }
}

#[test]
fn bootstrap_lexical_bounds_and_canonical_encoding_are_closed() {
    let valid = text(&raw());
    for prefix in [
        "",
        "SSPAIR-M2:",
        "sspair-m1:",
        "SSPAIR1:",
        "PAIR1-",
        " SSPAIR-M1:",
    ] {
        refuses(&format!("{prefix}{}", &valid[10..]), Error::Version);
    }
    refuses(&"x".repeat(3670), Error::Oversize);
    for suffix in [
        "", "A", "AA=", "AA==", "AB", "AAB", "+AAA", "/AAA", "AA\n", " AA", "é",
    ] {
        refuses(&format!("SSPAIR-M1:{suffix}"), Error::Encoding);
    }
    for suffix in [" ", "\n", "\t", "="] {
        refuses(&format!("{valid}{suffix}"), Error::Encoding);
    }
    let v = vectors();
    let mut max = v["bootstraps"][1]["bootstrap"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = max.last_mut().unwrap();
    let index = alphabet.iter().position(|c| c == last).unwrap();
    assert_eq!(index & 3, 0);
    *last = alphabet[index | 1];
    refuses(std::str::from_utf8(&max).unwrap(), Error::Encoding);
    assert_eq!(
        Bootstrap::recognise_pair(&valid, &" ".repeat(129), NOW).unwrap_err(),
        Error::Oversize
    );
    assert_eq!(
        Bootstrap::recognise_pair(&"x".repeat(3670), "", NOW).unwrap_err(),
        Error::Oversize
    );
}

#[test]
fn bootstrap_fixed_schema_rejects_nesting_extras_nonminimal_lengths_and_truncation() {
    let valid = raw();
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
    let mut cases = vec![vec![0x81; 2744]];
    let mut bad = valid.clone();
    bad.push(0);
    cases.push(bad);
    let mut bad = vec![0x98, 3];
    bad.extend_from_slice(&valid[1..]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad[0] = 0x9f;
    bad.push(0xff);
    cases.push(bad);
    let mut bad = vec![0x83, 0x79, 0, 26];
    bad.extend_from_slice(&valid[3..]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad[1] = 0x58;
    cases.push(bad);
    let mut bad = valid[..29].to_vec();
    bad.extend_from_slice(&[0x5a, 0, 0]);
    bad.extend_from_slice(&valid[30..]);
    cases.push(bad);
    let offset = valid.len() - 17;
    let mut bad = valid[..offset].to_vec();
    bad.extend_from_slice(&[0x58, 16]);
    bad.extend_from_slice(&valid[offset + 1..]);
    cases.push(bad);
    let mut bad = valid[..29].to_vec();
    bad.extend_from_slice(&[0x5b, 255, 255, 255, 255, 255, 255, 255, 255]);
    cases.push(bad);
    for bad in cases {
        refuses(&text(&bad), Error::Schema);
    }
    for member in 0..3 {
        for value in [
            Value::Null,
            Value::Array(vec![Value::Array(vec![])]),
            Value::Map(vec![]),
        ] {
            let mut f = fields(public.clone(), T.to_vec());
            f[member] = value;
            refuses(&text(&outer(f)), Error::Schema);
        }
    }
    for length in [0, 15, 17, 32] {
        refuses(
            &text(&outer(fields(public.clone(), vec![0; length]))),
            Error::Schema,
        );
    }
    let mut extra = fields(public.clone(), T.to_vec());
    extra.push(Value::Null);
    refuses(&text(&outer(extra)), Error::Schema);
    refuses(&text(&outer(fields(vec![], T.to_vec()))), Error::Schema);
    let mut version = fields(public, T.to_vec());
    version[0] = Value::Text("selfsame-pairing-manual/v2".into());
    refuses(&text(&outer(version)), Error::Version);
}

#[test]
fn carrier_commitment_key_and_exclusive_expiry_precede_typed_input() {
    let public = encode_carrier(&carrier()).unwrap();
    for bit in 0..128 {
        let mut wrong = T;
        wrong[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            Bootstrap::new(carrier(), wrong, NOW).unwrap_err(),
            Error::Commitment
        );
        refuses(
            &text(&outer(fields(public.clone(), wrong.to_vec()))),
            Error::Commitment,
        );
    }
    let mut wrong_m = input();
    wrong_m.mailbox_id[0] ^= 1;
    assert_eq!(
        Bootstrap::new(CredentialV2Carrier::new(wrong_m).unwrap(), T, NOW).unwrap_err(),
        Error::Commitment
    );
    let mut no_key = input();
    no_key.expected_allocator_key = None;
    let no_key = CredentialV2Carrier::new(no_key).unwrap();
    refuses(
        &text(&outer(fields(encode_carrier(&no_key).unwrap(), T.to_vec()))),
        Error::AllocatorKeyRequired,
    );
    for now in [NOW + 899, NOW + 900, NOW + 901] {
        assert_eq!(
            Bootstrap::recognise(&text(&raw()), now).is_ok(),
            now < NOW + 900
        );
    }
    for p in [vec![0xa0], vec![0xff], vec![0x81; 2000]] {
        refuses(&text(&outer(fields(p, T.to_vec()))), Error::Carrier);
    }
    let mut noncanonical = vec![0xb8, 11];
    noncanonical.extend_from_slice(&public[1..]);
    refuses(
        &text(&outer(fields(noncanonical, T.to_vec()))),
        Error::Carrier,
    );
}

#[test]
fn formats_never_fall_back_to_another_recognizer() {
    let words = Words::from_csprng([0; 4]);
    let manual = Bootstrap::new(carrier(), T, NOW).unwrap().encode().unwrap();
    let legacy = CredentialV2PresenceCode::new(*words.cpace_secret(), T).to_string();
    let full = CredentialV2Handoff::new(
        carrier(),
        CredentialV2PresenceCode::new(*words.cpace_secret(), T),
    )
    .unwrap()
    .encode()
    .unwrap();
    for input in [&*legacy, &*full, &*words.encode()] {
        assert!(Bootstrap::recognise(input, NOW).is_err());
    }
    for input in [&*manual, &*legacy, &*words.encode()] {
        assert!(input.parse::<CredentialV2Handoff>().is_err());
    }
    for input in [&*manual, &*full, &*words.encode()] {
        assert!(input.parse::<CredentialV2PresenceCode>().is_err());
    }
    for input in [&*manual, &*full, &*legacy] {
        assert!(input.parse::<Words>().is_err());
    }
}

#[test]
fn independent_real_cpace_and_finished_vector_uses_unchanged_context() {
    let v = vectors()["cpace"].clone();
    let carrier = decode_carrier(&bytes(&v["carrier_hex"])).unwrap();
    let profile = bytes(&v["profile_digest_hex"]).try_into().unwrap();
    let context = CredentialV2Context::derive(&carrier, profile).unwrap();
    assert_eq!(context.channel_identifier(), bytes(&v["ci_hex"]));
    assert_eq!(context.public_context(), bytes(&v["public_context_hex"]));
    let pc: Value = ciborium::de::from_reader(context.public_context()).unwrap();
    assert_eq!(pc.as_array().unwrap().len(), 13);
    assert_eq!(
        pc.as_array().unwrap()[9].as_bytes().unwrap(),
        carrier.carrier_ceremony_id()
    );
    let c: [u8; 16] = bytes(&v["c_hex"]).try_into().unwrap();
    assert_eq!(
        cpace::calculate_generator(&c, context.channel_identifier(), context.session_id())
            .unwrap()
            .as_slice(),
        bytes(&v["generator_hex"])
    );
    let presence = CredentialV2Presence::new(c, [0; 16]);
    let (a, am) = context
        .start_cpace(
            Side::Allocator,
            &presence,
            bytes(&v["allocator_scalar_hex"]).try_into().unwrap(),
        )
        .unwrap();
    let (b, bm) = context
        .start_cpace(
            Side::Claimant,
            &presence,
            bytes(&v["claimant_scalar_hex"]).try_into().unwrap(),
        )
        .unwrap();
    let af = encode_frame(&CredentialV2Frame::cpace(&am).unwrap()).unwrap();
    let bf = encode_frame(&CredentialV2Frame::cpace(&bm).unwrap()).unwrap();
    assert_eq!(am.share.as_slice(), bytes(&v["allocator_share_hex"]));
    assert_eq!(bm.share.as_slice(), bytes(&v["claimant_share_hex"]));
    assert_eq!(af, bytes(&v["allocator_frame_hex"]));
    assert_eq!(bf, bytes(&v["claimant_frame_hex"]));
    let aisk = cpace::finish(a, &bm).unwrap();
    let bisk = cpace::finish(b, &am).unwrap();
    assert_eq!(aisk.as_bytes().as_slice(), bytes(&v["isk_hex"]));
    assert_eq!(aisk.as_bytes(), bisk.as_bytes());
    let a =
        PendingCredentialV2Channel::new(Side::Allocator, aisk, context.public_context(), &af, &bf)
            .unwrap();
    let b =
        PendingCredentialV2Channel::new(Side::Claimant, bisk, context.public_context(), &af, &bf)
            .unwrap();
    let af = a.local_finished_frame();
    let bf = b.local_finished_frame();
    assert_eq!(
        af,
        CredentialV2Frame::Finished {
            side: Side::Allocator,
            value: bytes(&v["allocator_finished_hex"]).try_into().unwrap()
        }
    );
    assert_eq!(
        bf,
        CredentialV2Frame::Finished {
            side: Side::Claimant,
            value: bytes(&v["claimant_finished_hex"]).try_into().unwrap()
        }
    );
    let mut a = a.confirm(&bf).unwrap();
    let mut b = b.confirm(&af).unwrap();
    assert_eq!(a.transcript_hash().as_slice(), bytes(&v["th_hex"]));
    let frame = a.seal(b"unchanged application channel").unwrap();
    assert_eq!(b.open(&frame).unwrap(), b"unchanged application channel");
}
