//! SPEC-001 TEST-061, TEST-063, TEST-064, and TEST-066 Red Gate.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, decode_frame, decode_object, encode_carrier, encode_frame,
        CredentialV2Carrier, CredentialV2CarrierInput, CredentialV2Context, CredentialV2Frame,
        CredentialV2Kind, CredentialV2Object, CredentialV2Presence, PendingCredentialV2Channel,
        CONTROL_PADDING_BYTES, LARGE_PADDING_BYTES,
    },
    wire::{Direction, Side},
};
use ciborium::Value;
use sha2::{Digest, Sha256};

const MAILBOX: [u8; 32] = [0x11; 32];
const CEREMONY: [u8; 32] = [0x22; 32];
const NONCE: [u8; 32] = [0x33; 32];
const COMMITMENT: [u8; 32] = [0x44; 32];
const PROFILE_DIGEST: [u8; 32] = [0x55; 32];
const INTENT: [u8; 32] = [0x66; 32];

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: MAILBOX,
        carrier_ceremony_id: CEREMONY,
        carrier_nonce: NONCE,
        claim_commitment: COMMITMENT,
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: Some([0x77; 32]),
    })
    .expect("carrier")
}

fn canonical(value: &Value) -> Vec<u8> {
    cbor2::to_canonical_vec(value).expect("canonical test CBOR")
}

#[test]
fn test_061_carrier_and_context_are_separate_canonical_v2_values() {
    let carrier = carrier();
    let encoded = encode_carrier(&carrier).expect("carrier encodes");
    assert_eq!(decode_carrier(&encoded), Ok(carrier.clone()));
    let carrier_digest: [u8; 32] = Sha256::digest(&encoded).into();
    assert_eq!(carrier.digest(), carrier_digest);

    let context = CredentialV2Context::derive(&carrier, PROFILE_DIGEST).expect("context");
    assert_eq!(context.session_id(), &MAILBOX);
    assert_eq!(context.carrier_ceremony_id(), &CEREMONY);
    assert_eq!(context.carrier_digest(), &carrier.digest());

    let Value::Array(public) =
        ciborium::de::from_reader(context.public_context()).expect("public context decodes")
    else {
        panic!("public context is an array")
    };
    assert_eq!(public.len(), 13);
    assert_eq!(
        public[0].as_text(),
        Some("cbcl-pairing-public-context/credential-v2")
    );
    assert_eq!(public[1], Value::Integer(2.into()));

    let Value::Array(ci) = ciborium::de::from_reader(context.channel_identifier())
        .expect("channel identifier decodes")
    else {
        panic!("channel identifier is an array")
    };
    assert_eq!(ci[0].as_text(), Some("cbcl-pairing-ci/credential-v2"));
    assert_eq!(ci[1], Value::Integer(2.into()));
    assert_ne!(context.public_context(), context.channel_identifier());
}

#[test]
fn test_061_v2_cpace_finished_aad_and_ciphertext_interoperate() {
    let carrier = carrier();
    let context = CredentialV2Context::derive(&carrier, PROFILE_DIGEST).expect("context");
    let presence_a = CredentialV2Presence::new([0x88; 16], [0x99; 16]);
    let presence_b = CredentialV2Presence::new([0x88; 16], [0x99; 16]);

    let (allocator_state, allocator_message) = context
        .start_cpace(Side::Allocator, &presence_a, [0x0a; 32])
        .expect("allocator CPace");
    let (claimant_state, claimant_message) = context
        .start_cpace(Side::Claimant, &presence_b, [0x0b; 32])
        .expect("claimant CPace");
    let isk_a = cpace::finish(allocator_state, &claimant_message).expect("allocator ISK");
    let isk_b = cpace::finish(claimant_state, &allocator_message).expect("claimant ISK");

    let allocator_frame = CredentialV2Frame::cpace(&allocator_message).expect("allocator frame");
    let claimant_frame = CredentialV2Frame::cpace(&claimant_message).expect("claimant frame");
    let allocator_bytes = encode_frame(&allocator_frame).expect("frame encodes");
    let claimant_bytes = encode_frame(&claimant_frame).expect("frame encodes");
    assert_eq!(decode_frame(&allocator_bytes), Ok(allocator_frame));
    assert_eq!(decode_frame(&claimant_bytes), Ok(claimant_frame));

    let pending_a = PendingCredentialV2Channel::new(
        Side::Allocator,
        isk_a,
        context.public_context(),
        &allocator_bytes,
        &claimant_bytes,
    )
    .expect("allocator schedule");
    let pending_b = PendingCredentialV2Channel::new(
        Side::Claimant,
        isk_b,
        context.public_context(),
        &allocator_bytes,
        &claimant_bytes,
    )
    .expect("claimant schedule");
    assert_eq!(pending_a.transcript_hash(), pending_b.transcript_hash());

    let finished_a = pending_a.local_finished_frame();
    let finished_b = pending_b.local_finished_frame();
    assert_eq!(
        decode_frame(&encode_frame(&finished_a).unwrap()),
        Ok(finished_a.clone())
    );
    assert_eq!(
        decode_frame(&encode_frame(&finished_b).unwrap()),
        Ok(finished_b.clone())
    );
    let mut channel_a = pending_a.confirm(&finished_b).expect("claimant Finished");
    let mut channel_b = pending_b.confirm(&finished_a).expect("allocator Finished");

    let offer = CredentialV2Object::new(CredentialV2Kind::Offer, INTENT, vec![0xa1, 0x01, 0x02])
        .expect("offer object");
    let sealed = channel_a.seal(offer.as_bytes()).expect("seal offer");
    assert_eq!(sealed.direction(), Some(Direction::AllocatorToClaimant));
    let opened = channel_b.open(&sealed).expect("open offer");
    assert_eq!(opened, offer.as_bytes());
    assert_eq!(decode_object(&opened), Ok(offer));
}

#[test]
fn test_063_object_kind_arms_padding_and_lengths_are_exact() {
    for (number, kind) in CredentialV2Kind::ALL.into_iter().enumerate() {
        assert_eq!(kind.number(), number as u8);
        let body = vec![0x01];
        let object = CredentialV2Object::new(kind, INTENT, body.clone()).expect("object");
        assert_eq!(object.body(), body);
        assert_eq!(decode_object(object.as_bytes()), Ok(object.clone()));
        let expected_padding = if kind.is_large() {
            LARGE_PADDING_BYTES
        } else {
            CONTROL_PADDING_BYTES
        };
        assert_eq!(object.padding_len(), expected_padding);
        let content_hash: [u8; 32] = Sha256::digest(object.as_bytes()).into();
        assert_eq!(object.content_hash(), content_hash);
    }

    for accepted in [1, 23, 24, 255, 256, 2_047, 2_048] {
        assert!(CredentialV2Object::new(
            CredentialV2Kind::Preparation,
            INTENT,
            vec![0x01; accepted]
        )
        .is_ok());
    }
    for refused in [0, 2_049, 4_095, 4_096] {
        assert!(CredentialV2Object::new(
            CredentialV2Kind::Preparation,
            INTENT,
            vec![0x01; refused]
        )
        .is_err());
    }
    assert!(CredentialV2Object::new(CredentialV2Kind::Payload, INTENT, vec![0x01; 62_000]).is_ok());
    assert!(
        CredentialV2Object::new(CredentialV2Kind::Payload, INTENT, vec![0x01; 62_001]).is_err()
    );
}

#[test]
fn test_063_wrong_arm_or_padding_refuses() {
    let wrong_arm = canonical(&Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(2.into())),
        (Value::Integer(1.into()), Value::Integer(9.into())),
        (Value::Integer(2.into()), Value::Bytes(INTENT.to_vec())),
        (Value::Integer(3.into()), Value::Bytes(vec![1])),
        (
            Value::Integer(4.into()),
            Value::Bytes(vec![0; CONTROL_PADDING_BYTES]),
        ),
    ]));
    assert!(decode_object(&wrong_arm).is_err());

    let mut bad_padding =
        CredentialV2Object::new(CredentialV2Kind::IntentApprove, INTENT, vec![0x01])
            .expect("control object")
            .into_bytes();
    *bad_padding.last_mut().expect("padding byte") = 1;
    assert!(decode_object(&bad_padding).is_err());
}
