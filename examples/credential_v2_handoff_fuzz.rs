//! Bounded, deterministic recognizer fuzz harness for SPEC-077 TEST-006.
//! Run: cargo run --example credential_v2_handoff_fuzz -- 10000
//! Synthetic inputs only; no I/O except aggregate results. Maximum input: 4096 bytes.
use base64ct::{Base64UrlUnpadded, Encoding};
use cbcl_pairing::credential_v2::{encode_carrier, CredentialV2Handoff, CredentialV2HandoffError};

const MAX_INPUT: usize = 4096;
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn exercise(input: &[u8], counts: &mut [usize; 8]) {
    assert!(input.len() <= MAX_INPUT);
    let Ok(text) = std::str::from_utf8(input) else {
        counts[7] += 1;
        return;
    };
    match text.parse::<CredentialV2Handoff>() {
        Ok(handoff) => {
            assert!(text.len() <= 3691);
            assert_eq!(handoff.encode().unwrap().as_bytes(), input);
            let public = encode_carrier(handoff.carrier()).unwrap();
            assert!(public.len() <= 2695);
            let digest = handoff.carrier().digest();
            let (carrier, presence) = handoff.into_parts();
            let rebuilt = CredentialV2Handoff::new(carrier, presence).unwrap();
            assert_eq!(rebuilt.carrier().digest(), digest);
            assert_eq!(rebuilt.encode().unwrap().as_bytes(), input);
            counts[0] += 1;
        }
        Err(error) => {
            let index = match error {
                CredentialV2HandoffError::Version => 1,
                CredentialV2HandoffError::Oversize => 2,
                CredentialV2HandoffError::Encoding => 3,
                CredentialV2HandoffError::Schema => 4,
                CredentialV2HandoffError::Carrier => 5,
                CredentialV2HandoffError::Commitment => 6,
            };
            if text.len() > 3691 {
                assert_eq!(index, 2);
            }
            counts[index] += 1;
        }
    }
}

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .map(|n| n.parse::<usize>().expect("integer budget"))
        .unwrap_or(10000);
    assert!((1..=1_000_000).contains(&iterations));
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/credential-v2-handoff.json")).unwrap();
    let texts: Vec<&str> = vectors
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["handoff"].as_str().unwrap())
        .collect();
    let decoded: Vec<Vec<u8>> = texts
        .iter()
        .map(|s| Base64UrlUnpadded::decode_vec(&s[8..]).unwrap())
        .collect();
    let mut rng = Rng(0x0770_0006_cafe_f00d);
    let mut counts = [0; 8];
    for index in 0..iterations {
        let seed = index % texts.len();
        // Valid seeds exercise both extremes; mutations cross each recognizer layer.
        exercise(texts[seed].as_bytes(), &mut counts);
        let length = rng.next() as usize % (MAX_INPUT + 1);
        exercise(&rng.bytes(length), &mut counts);
        let mut lexical = rng.bytes(length);
        for b in &mut lexical {
            *b &= 0x7f;
        }
        exercise(&lexical, &mut counts);
        let length = rng.next() as usize % 2764;
        let raw = rng.bytes(length);
        exercise(
            format!("SSPAIR1:{}", Base64UrlUnpadded::encode_string(&raw)).as_bytes(),
            &mut counts,
        );
        let mut input = texts[seed].as_bytes().to_vec();
        let position = rng.next() as usize % input.len();
        input[position] ^= (rng.next() as u8) | 1;
        exercise(&input, &mut counts);
        let mut input = decoded[seed].clone();
        match index % 6 {
            0 => {
                let n = rng.next() as usize % input.len();
                input.truncate(n);
            }
            1 => input.push(0),
            2 => {
                let n = rng.next() as usize % input.len();
                input[n] ^= 1;
            }
            3 => {
                let n = input.len() - 1;
                input[n] ^= 1;
            } // T, otherwise valid.
            4 => input[33] ^= 1,  // Inside the public carrier.
            _ => input[0] = 0x9f, // Indefinite outer array.
        }
        exercise(
            format!("SSPAIR1:{}", Base64UrlUnpadded::encode_string(&input)).as_bytes(),
            &mut counts,
        );
        // Keep the outer language valid while feeding arbitrary bytes to its
        // existing public-carrier decoder, including deeply nested containers.
        let n = rng.next() as usize % 2696;
        let public = if index % 2 == 0 {
            rng.bytes(n)
        } else {
            vec![0x81; n]
        };
        let input = cbor2::to_canonical_vec(&ciborium::Value::Array(vec![
            ciborium::Value::Text("selfsame-pairing-handoff/v1".into()),
            ciborium::Value::Bytes(public),
            ciborium::Value::Bytes(vec![0; 16]),
            ciborium::Value::Bytes(vec![0; 16]),
        ]))
        .unwrap();
        exercise(
            format!("SSPAIR1:{}", Base64UrlUnpadded::encode_string(&input)).as_bytes(),
            &mut counts,
        );
    }
    println!(
        "seed=0x07700006cafef00d iterations={iterations} max_input={MAX_INPUT} cases={}",
        counts.iter().sum::<usize>()
    );
    println!("accepted={} version={} oversize={} encoding={} schema={} carrier={} commitment={} non_utf8={}",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6], counts[7]);
    assert!(
        counts.iter().all(|n| *n > 0),
        "budget must exercise every outcome"
    );
}
