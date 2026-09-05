//! SPEC-078 TEST-002: bounded deterministic recognizer/property harness.
//! Synthetic values only. Run: cargo run --example credential_v2_manual_fuzz -- 10000
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::credential_v2::{
    CredentialV2ManualBootstrap as Bootstrap, CredentialV2ManualError as Error,
    CredentialV2ManualWords as Words,
};
const MAX_INPUT: usize = 4096;
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}
fn exercise(raw: &[u8], counts: &mut [usize; 10]) {
    assert!(raw.len() <= MAX_INPUT);
    let Ok(text) = std::str::from_utf8(raw) else {
        counts[9] += 1;
        return;
    };
    let error = match Bootstrap::recognise(text, 0) {
        Ok(value) => {
            assert!(text.len() <= 3669);
            assert_eq!(value.encode().unwrap().as_bytes(), raw);
            assert!(value.carrier().expected_allocator_key().is_some());
            None
        }
        Err(error) => Some(error),
    };
    if text.len() > 3669 {
        assert_eq!(error, Some(Error::Oversize));
    }
    let index = match error {
        None => 0,
        Some(Error::Version) => 1,
        Some(Error::Oversize) => 2,
        Some(Error::Encoding) => 3,
        Some(Error::Schema) => 4,
        Some(Error::Carrier) => 5,
        Some(Error::Commitment) => 6,
        Some(Error::Expired) => 7,
        Some(Error::AllocatorKeyRequired) => 8,
        Some(Error::Checksum) => unreachable!(),
    };
    counts[index] += 1;
}
fn exercise_words(raw: &[u8], counts: &mut [usize; 5]) {
    assert!(raw.len() <= MAX_INPUT);
    let Ok(text) = std::str::from_utf8(raw) else {
        return;
    };
    let result = text.parse::<Words>();
    if text.len() > 128 {
        assert!(matches!(result, Err(Error::Oversize)));
    }
    let index = match result {
        Ok(words) => {
            let canonical = words.encode();
            assert!(canonical.len() <= 26);
            assert_eq!(
                canonical.parse::<Words>().unwrap().cpace_secret(),
                words.cpace_secret()
            );
            0
        }
        Err(Error::Oversize) => 1,
        Err(Error::Encoding) => 2,
        Err(Error::Schema) => 3,
        Err(Error::Checksum) => 4,
        _ => unreachable!(),
    };
    counts[index] += 1;
}
fn main() {
    let budget = std::env::args()
        .nth(1)
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(10000);
    assert!((1..=1_000_000).contains(&budget));
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/credential-v2-manual.json")).unwrap();
    let seeds: Vec<_> = vectors["bootstraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["bootstrap"].as_str().unwrap())
        .collect();
    let decoded: Vec<_> = seeds
        .iter()
        .map(|s| Base64UrlUnpadded::decode_vec(&s[10..]).unwrap())
        .collect();
    let mut rng = Rng(0x0780_0002_cafe_f00d);
    let mut bootstrap_counts = [0; 10];
    let mut word_counts = [0; 5];
    for i in 0..budget {
        let seed = i % seeds.len();
        exercise(seeds[seed].as_bytes(), &mut bootstrap_counts);
        let len = rng.next() as usize % (MAX_INPUT + 1);
        let mut bytes = rng.bytes(len);
        exercise(&bytes, &mut bootstrap_counts);
        exercise_words(&bytes, &mut word_counts);
        for b in &mut bytes {
            *b &= 127;
        }
        exercise(&bytes, &mut bootstrap_counts);
        exercise_words(&bytes, &mut word_counts);
        let mut raw = decoded[seed].clone();
        match i % 5 {
            0 => {
                let p = rng.next() as usize % raw.len();
                raw[p] ^= 1;
            }
            1 => {
                let p = rng.next() as usize % raw.len();
                raw.truncate(p);
            }
            2 => raw.push(0),
            3 => {
                let p = raw.len() - 1;
                raw[p] ^= 1;
            }
            _ => raw[0] = 0x9f,
        }
        let text = format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(&raw));
        exercise(text.as_bytes(), &mut bootstrap_counts);
        // Valid outer schema around arbitrary or deeply nested carrier bytes.
        let len = rng.next() as usize % 2696;
        let public = if i % 2 == 0 {
            rng.bytes(len)
        } else {
            vec![0x81; len]
        };
        let raw = cbor2::to_canonical_vec(&ciborium::Value::Array(vec![
            ciborium::Value::Text("selfsame-pairing-manual/v1".into()),
            ciborium::Value::Bytes(public),
            ciborium::Value::Bytes(vec![0; 16]),
        ]))
        .unwrap();
        exercise(
            format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(&raw)).as_bytes(),
            &mut bootstrap_counts,
        );
        // Generated valid domain and all accepted normalization classes.
        let random = (rng.next() as u32).to_be_bytes();
        let words = Words::from_csprng(random);
        let canonical = words.encode();
        assert_eq!(
            &words.cpace_secret()[12..],
            &(u32::from_be_bytes(random) & 0x3fff_ffff).to_be_bytes()
        );
        exercise_words(canonical.as_bytes(), &mut word_counts);
        let normalized = format!(
            "\t {}\r",
            canonical.to_ascii_uppercase().replace(' ', "\n\t")
        );
        assert_eq!(
            normalized.parse::<Words>().unwrap().cpace_secret(),
            words.cpace_secret()
        );
        exercise_words(normalized.as_bytes(), &mut word_counts);
        let mut phrase = canonical.as_bytes().to_vec();
        let p = rng.next() as usize % phrase.len();
        phrase[p] ^= 1;
        exercise_words(&phrase, &mut word_counts);
        let list = bip39::Language::English.word_list();
        let random_phrase = (0..3)
            .map(|_| list[rng.next() as usize % 2048])
            .collect::<Vec<_>>()
            .join(" ");
        exercise_words(random_phrase.as_bytes(), &mut word_counts);
    }
    // Explicit valid outer/carrier seeds reach key-required and expiry outcomes.
    for missing_key in [true, false] {
        let mut wrapper: ciborium::Value =
            ciborium::de::from_reader(decoded[0].as_slice()).unwrap();
        let fields = wrapper.as_array_mut().unwrap();
        let mut public: ciborium::Value =
            ciborium::de::from_reader(fields[1].as_bytes().unwrap().as_slice()).unwrap();
        let map = public.as_map_mut().unwrap();
        if missing_key {
            map.retain(|(key, _)| key.as_text() != Some("expected-allocator-key"));
        } else {
            map.iter_mut()
                .find(|(key, _)| key.as_text() == Some("relay-expires-at"))
                .unwrap()
                .1 = ciborium::Value::Integer(0.into());
        }
        fields[1] = ciborium::Value::Bytes(cbor2::to_canonical_vec(&public).unwrap());
        let raw = cbor2::to_canonical_vec(&wrapper).unwrap();
        exercise(
            format!("SSPAIR-M1:{}", Base64UrlUnpadded::encode_string(&raw)).as_bytes(),
            &mut bootstrap_counts,
        );
    }
    exercise_words("é".as_bytes(), &mut word_counts);
    println!("seed=0x07800002cafef00d iterations={budget} max_input={MAX_INPUT}");
    println!("bootstrap outcomes (ok/version/oversize/encoding/schema/carrier/commitment/expired/key/nonutf8)={bootstrap_counts:?}");
    println!("phrase outcomes (ok/oversize/encoding/schema/checksum)={word_counts:?}");
    assert!(bootstrap_counts.iter().all(|n| *n > 0));
    assert!(word_counts.iter().all(|n| *n > 0));
}
