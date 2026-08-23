//! SPEC-001 TEST-061 and TEST-064 Red Gate: credential/v2 choreography.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        credential_v2_intent_digest, encode_frame, CredentialV2AccountProvenance,
        CredentialV2Advance, CredentialV2BodyVerifier, CredentialV2Carrier,
        CredentialV2CarrierInput, CredentialV2CheckpointNonce, CredentialV2Context,
        CredentialV2DeviceBinding, CredentialV2Endpoint, CredentialV2Error, CredentialV2Frame,
        CredentialV2IntentAuthority, CredentialV2IntentClaims, CredentialV2IntentInput,
        CredentialV2IntentVerifier, CredentialV2Kind, CredentialV2LogicalBody, CredentialV2Object,
        CredentialV2OfferParser, CredentialV2Phase, CredentialV2Presence, CredentialV2RelayState,
        CredentialV2TofuState, CredentialV2Transition, PendingCredentialV2Channel,
        SecureCredentialV2Channel,
    },
    wire::Side,
};
use ciborium::Value;

const CEREMONY: [u8; 32] = [0x21; 32];
const OFFER_CORE: [u8; 32] = [0x22; 32];

fn intent() -> [u8; 32] {
    credential_v2_intent_digest(OFFER_CORE)
}

fn claims() -> CredentialV2IntentClaims {
    CredentialV2IntentClaims::new(
        "https://chat.anuna.io/selfsame/v2",
        "https://chat.anuna.io",
        "https://chat.anuna.io:9443",
        CEREMONY,
        CredentialV2AccountProvenance::new([0x31; 32], [0x32; 32]),
        vec!["https://chat.anuna.io/selfsame/v2#chat-send".into()],
        CredentialV2DeviceBinding::new(format!("did:key:z6Mk{}", "1".repeat(44)), [0x33; 32])
            .unwrap(),
        CredentialV2Transition::NoTransition,
        OFFER_CORE,
    )
    .unwrap()
}

#[derive(Debug)]
struct Parser;

impl CredentialV2OfferParser for Parser {
    fn parse_signed_offer(
        &mut self,
        body: &[u8],
    ) -> Result<CredentialV2IntentClaims, CredentialV2Error> {
        (body == [0x81])
            .then(claims)
            .ok_or(CredentialV2Error::Profile)
    }
}

#[derive(Debug)]
struct IntentVerifier;

impl CredentialV2IntentVerifier for IntentVerifier {
    fn verify(
        &mut self,
        peer: &CredentialV2IntentInput,
        authority: &CredentialV2IntentAuthority,
    ) -> Result<(), CredentialV2Error> {
        (peer.carrier_ceremony_id() == authority.carrier_ceremony_id())
            .then_some(())
            .ok_or(CredentialV2Error::Profile)
    }
}

#[derive(Debug, Default)]
struct BodyVerifier {
    calls: usize,
    refuse: bool,
}

impl CredentialV2BodyVerifier for BodyVerifier {
    fn verify(&mut self, body: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        self.calls += 1;
        assert_ne!(body.kind(), CredentialV2Kind::Offer);
        assert_eq!(body.carrier_ceremony_id(), &CEREMONY);
        assert!(!body.bytes().is_empty());
        if self.refuse {
            Err(CredentialV2Error::Profile)
        } else {
            Ok(())
        }
    }
}

fn authority() -> CredentialV2IntentAuthority {
    CredentialV2IntentAuthority::new(claims(), CredentialV2TofuState::NewPair).unwrap()
}

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: [0x41; 32],
        carrier_ceremony_id: CEREMONY,
        carrier_nonce: [0x42; 32],
        claim_commitment: [0x43; 32],
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: Some([0x44; 32]),
    })
    .unwrap()
}

fn secure_channels() -> (SecureCredentialV2Channel, SecureCredentialV2Channel) {
    let context = CredentialV2Context::derive(&carrier(), [0x51; 32]).unwrap();
    let allocator_presence = CredentialV2Presence::new([0x52; 16], [0x53; 16]);
    let claimant_presence = CredentialV2Presence::new([0x52; 16], [0x53; 16]);
    let (allocator_state, allocator_message) = context
        .start_cpace(Side::Allocator, &allocator_presence, [0x54; 32])
        .unwrap();
    let (claimant_state, claimant_message) = context
        .start_cpace(Side::Claimant, &claimant_presence, [0x55; 32])
        .unwrap();
    let isk_a = cpace::finish(allocator_state, &claimant_message).unwrap();
    let isk_b = cpace::finish(claimant_state, &allocator_message).unwrap();
    let allocator_frame =
        encode_frame(&CredentialV2Frame::cpace(&allocator_message).unwrap()).unwrap();
    let claimant_frame =
        encode_frame(&CredentialV2Frame::cpace(&claimant_message).unwrap()).unwrap();
    let pending_a = PendingCredentialV2Channel::new(
        Side::Allocator,
        isk_a,
        context.public_context(),
        &allocator_frame,
        &claimant_frame,
    )
    .unwrap();
    let pending_b = PendingCredentialV2Channel::new(
        Side::Claimant,
        isk_b,
        context.public_context(),
        &allocator_frame,
        &claimant_frame,
    )
    .unwrap();
    let finished_a = pending_a.local_finished_frame();
    let finished_b = pending_b.local_finished_frame();
    (
        pending_a.confirm(&finished_b).unwrap(),
        pending_b.confirm(&finished_a).unwrap(),
    )
}

fn offer() -> CredentialV2Object {
    CredentialV2Object::new(CredentialV2Kind::Offer, intent(), vec![0x81]).unwrap()
}

fn successor(kind: CredentialV2Kind, predecessor: &CredentialV2Object) -> CredentialV2Object {
    let mut entries = vec![
        (
            Value::Text("carrierCeremonyId".into()),
            Value::Bytes(CEREMONY.to_vec()),
        ),
        (
            Value::Text("predecessorDigest".into()),
            Value::Bytes(predecessor.content_hash().to_vec()),
        ),
    ];
    if kind == CredentialV2Kind::Receipt {
        entries.extend([
            (
                Value::Text("finalStatusJws".into()),
                Value::Text("e30.e30.AA".into()),
            ),
            (
                Value::Text("finalStatusDigest".into()),
                Value::Bytes(vec![0x71; 32]),
            ),
        ]);
    } else {
        entries.push((Value::Text("fixture".into()), Value::Integer(1.into())));
    }
    let body = cbor2::to_canonical_vec(&Value::Map(entries)).unwrap();
    CredentialV2Object::new(kind, intent(), body).unwrap()
}

fn endpoints() -> (CredentialV2Endpoint, CredentialV2Endpoint) {
    (
        CredentialV2Endpoint::new(
            Side::Allocator,
            carrier(),
            Box::new(BodyVerifier::default()),
        ),
        CredentialV2Endpoint::new(Side::Claimant, carrier(), Box::new(BodyVerifier::default())),
    )
}

#[test]
fn test_061_full_choreography_sender_predecessor_and_terminal_are_exact() {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    assert_eq!(allocator.send(&offer), Ok(CredentialV2Advance::Advanced));
    let effect = claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .expect("offer display");
    assert!(matches!(effect, CredentialV2Advance::DisplayIntent(_)));
    assert_eq!(allocator.phase(), CredentialV2Phase::Offered);
    assert_eq!(claimant.phase(), CredentialV2Phase::Offered);

    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    exchange(&mut claimant, &mut allocator, &approve);
    let preparation = successor(CredentialV2Kind::Preparation, &approve);
    exchange(&mut claimant, &mut allocator, &preparation);
    let comparison = successor(CredentialV2Kind::ComparisonConfirmed, &preparation);
    exchange(&mut allocator, &mut claimant, &comparison);
    let final_approve = successor(CredentialV2Kind::FinalApprove, &comparison);
    exchange(&mut claimant, &mut allocator, &final_approve);
    let payload = successor(CredentialV2Kind::Payload, &final_approve);
    exchange(&mut claimant, &mut allocator, &payload);
    assert_eq!(claimant.phase(), CredentialV2Phase::PayloadSent);

    let receipt = successor(CredentialV2Kind::Receipt, &payload);
    exchange(&mut allocator, &mut claimant, &receipt);
    assert_eq!(allocator.phase(), CredentialV2Phase::Terminal);
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);
}

#[test]
fn test_061_only_exact_latest_retransmission_is_idempotent() {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    assert_eq!(allocator.send(&offer), Ok(CredentialV2Advance::Advanced));
    assert_eq!(
        allocator.send(&offer),
        Ok(CredentialV2Advance::ExactRetransmission)
    );
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    assert_eq!(
        claimant
            .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier,)
            .unwrap(),
        CredentialV2Advance::ExactRetransmission
    );

    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    exchange(&mut claimant, &mut allocator, &approve);
    assert_eq!(
        allocator.receive(&approve),
        Ok(CredentialV2Advance::ExactRetransmission)
    );
    assert_eq!(allocator.receive(&offer), Err(CredentialV2Error::Direction));
    assert_eq!(allocator.phase(), CredentialV2Phase::Terminal);
}

#[test]
fn test_061_wrong_sender_predecessor_intent_and_verifier_refusal_are_terminal() {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    allocator.send(&offer).unwrap();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    assert_eq!(allocator.send(&approve), Err(CredentialV2Error::Direction));
    assert_eq!(allocator.phase(), CredentialV2Phase::Terminal);

    let (_, mut claimant) = endpoints();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let wrong_predecessor = successor(
        CredentialV2Kind::IntentApprove,
        &CredentialV2Object::new(CredentialV2Kind::Offer, intent(), vec![0x82]).unwrap(),
    );
    assert_eq!(
        claimant.send(&wrong_predecessor),
        Err(CredentialV2Error::Predecessor)
    );
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);

    let (_, mut claimant) = endpoints();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let mut wrong_intent = successor(CredentialV2Kind::IntentApprove, &offer);
    wrong_intent = CredentialV2Object::new(
        CredentialV2Kind::IntentApprove,
        [0xfe; 32],
        wrong_intent.body().to_vec(),
    )
    .unwrap();
    assert_eq!(
        claimant.send(&wrong_intent),
        Err(CredentialV2Error::Profile)
    );
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);

    let mut refusing = CredentialV2Endpoint::new(
        Side::Claimant,
        carrier(),
        Box::new(BodyVerifier {
            calls: 0,
            refuse: true,
        }),
    );
    refusing
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    assert_eq!(refusing.send(&approve), Err(CredentialV2Error::Profile));
    assert_eq!(refusing.phase(), CredentialV2Phase::Terminal);
}

#[test]
fn test_064_post_payload_refusal_neither_advances_nor_erases_receipt_wait() {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    allocator.send(&offer).unwrap();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    exchange(&mut claimant, &mut allocator, &approve);
    let preparation = successor(CredentialV2Kind::Preparation, &approve);
    exchange(&mut claimant, &mut allocator, &preparation);
    let binding = successor(CredentialV2Kind::BindingConfirmed, &preparation);
    exchange(&mut allocator, &mut claimant, &binding);
    let final_approve = successor(CredentialV2Kind::FinalApprove, &binding);
    exchange(&mut claimant, &mut allocator, &final_approve);
    let payload = successor(CredentialV2Kind::Payload, &final_approve);
    exchange(&mut claimant, &mut allocator, &payload);
    let refusal = successor(CredentialV2Kind::Refusal, &payload);

    assert_eq!(claimant.send(&refusal), Err(CredentialV2Error::Phase));
    assert_eq!(allocator.receive(&refusal), Err(CredentialV2Error::Phase));
    assert_eq!(claimant.phase(), CredentialV2Phase::PayloadSent);
    assert_eq!(allocator.phase(), CredentialV2Phase::PayloadSent);

    let receipt = successor(CredentialV2Kind::Receipt, &payload);
    exchange(&mut allocator, &mut claimant, &receipt);
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);
}

#[test]
fn test_067_recovered_receipt_uses_registered_verifier_and_same_terminal_reducer() {
    let (mut allocator, mut claimant, payload) = endpoints_at_payload();
    let receipt = successor(CredentialV2Kind::Receipt, &payload);

    let authority = claimant
        .authenticate_recovered_receipt(&receipt)
        .expect("registered verifier authenticates recovery");
    assert_eq!(claimant.phase(), CredentialV2Phase::PayloadSent);
    assert_eq!(
        claimant.recover_receipt(&receipt, authority),
        Ok(CredentialV2Advance::Advanced)
    );
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);

    assert_eq!(
        allocator.receive(&receipt),
        Err(CredentialV2Error::Direction)
    );
}

#[test]
fn test_067_recovery_mismatch_and_post_payload_refusal_leave_receipt_pending() {
    let (_, mut claimant, payload) = endpoints_at_payload();
    let receipt = successor(CredentialV2Kind::Receipt, &payload);
    let authority = claimant
        .authenticate_recovered_receipt(&receipt)
        .expect("authority");
    let mut other = successor(CredentialV2Kind::Receipt, &payload);
    let mut body: Value = ciborium::de::from_reader(other.body()).unwrap();
    let Value::Map(entries) = &mut body else {
        panic!("receipt map")
    };
    let digest = entries
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("finalStatusDigest"))
        .map(|(_, value)| value)
        .unwrap();
    *digest = Value::Bytes(vec![0x72; 32]);
    other = CredentialV2Object::new(
        CredentialV2Kind::Receipt,
        intent(),
        cbor2::to_canonical_vec(&body).unwrap(),
    )
    .unwrap();

    assert_eq!(
        claimant.recover_receipt(&other, authority),
        Err(CredentialV2Error::Profile)
    );
    assert_eq!(claimant.phase(), CredentialV2Phase::PayloadSent);

    let refusal = successor(CredentialV2Kind::Refusal, &payload);
    assert_eq!(claimant.receive(&refusal), Err(CredentialV2Error::Phase));
    let authority = claimant
        .authenticate_recovered_receipt(&receipt)
        .expect("recovery remains available");
    claimant
        .recover_receipt(&receipt, authority)
        .expect("recovered receipt");
    assert_eq!(claimant.phase(), CredentialV2Phase::Terminal);
}

#[test]
fn test_065_sealed_checkpoint_restores_exact_payload_receipt_wait() {
    let (mut allocator, mut claimant, final_approve) = endpoints_at_final_approved();
    let payload = successor(CredentialV2Kind::Payload, &final_approve);
    let (mut allocator_channel, mut claimant_channel) = secure_channels();
    let mut relay = CredentialV2RelayState::new([0xa3; 32]);
    let cached = claimant
        .prepare_outbound(&payload, &mut claimant_channel, &mut relay)
        .expect("payload sealed once");
    assert_eq!(allocator_channel.open(&cached).unwrap(), payload.as_bytes());
    allocator.receive(&payload).unwrap();
    let wrapping_key = [0xa1; 32];
    let checkpoint = claimant
        .seal_checkpoint(
            &claimant_channel,
            &relay,
            &wrapping_key,
            1,
            None,
            CredentialV2CheckpointNonce::from_csprng([0xa2; 12]),
            1_800_000_800,
        )
        .expect("claimant retained checkpoint");

    let restored = CredentialV2Endpoint::restore_checkpoint(
        checkpoint.as_bytes(),
        &wrapping_key,
        Side::Claimant,
        &carrier(),
        1,
        1_900_000_000,
        Box::new(BodyVerifier::default()),
    )
    .expect("null-expiry payload checkpoint outlives relay");
    let (mut restored, mut restored_channel, mut restored_relay) = restored.into_parts();
    assert_eq!(restored.phase(), CredentialV2Phase::PayloadSent);
    assert_eq!(restored_relay.membership_token(), relay.membership_token());
    assert_eq!(restored_relay.cached_outbound_frame(), Some(&cached));
    assert_eq!(
        restored
            .prepare_outbound(&payload, &mut restored_channel, &mut restored_relay)
            .unwrap(),
        cached
    );
}

#[test]
fn test_065_checkpoint_bindings_expiry_generation_and_nonce_are_closed() {
    let (mut allocator, mut claimant, _) = endpoints_at_payload();
    let (allocator_channel, claimant_channel) = secure_channels();
    let allocator_relay = CredentialV2RelayState::new([0xb3; 32]);
    let claimant_relay = CredentialV2RelayState::new([0xb4; 32]);
    let wrapping_key = [0xb1; 32];
    assert!(matches!(
        allocator.seal_checkpoint(
            &allocator_channel,
            &allocator_relay,
            &wrapping_key,
            1,
            None,
            CredentialV2CheckpointNonce::from_csprng([0xb2; 12]),
            1_800_000_800,
        ),
        Err(CredentialV2Error::Schema)
    ));
    assert!(matches!(
        claimant.seal_checkpoint(
            &claimant_channel,
            &claimant_relay,
            &wrapping_key,
            1,
            Some(1_800_000_900),
            CredentialV2CheckpointNonce::from_csprng([0xb2; 12]),
            1_800_000_800,
        ),
        Err(CredentialV2Error::Schema)
    ));

    let checkpoint = allocator
        .seal_checkpoint(
            &allocator_channel,
            &allocator_relay,
            &wrapping_key,
            1,
            Some(1_800_000_900),
            CredentialV2CheckpointNonce::from_csprng([0xb2; 12]),
            1_800_000_800,
        )
        .unwrap();
    let Value::Array(outer) = ciborium::de::from_reader(checkpoint.as_bytes()).unwrap() else {
        panic!("checkpoint array")
    };
    assert_eq!(outer.len(), 9);
    assert_eq!(outer[4].as_bytes().unwrap(), &CEREMONY);
    assert!(outer[8].as_bytes().unwrap().len() <= 69_632);
    assert!(matches!(
        allocator.seal_checkpoint(
            &allocator_channel,
            &allocator_relay,
            &wrapping_key,
            2,
            Some(1_800_000_900),
            CredentialV2CheckpointNonce::from_csprng([0xb2; 12]),
            1_800_000_800,
        ),
        Err(CredentialV2Error::Counter)
    ));
    assert!(CredentialV2Endpoint::restore_checkpoint(
        checkpoint.as_bytes(),
        &[0xff; 32],
        Side::Allocator,
        &carrier(),
        1,
        1_800_000_800,
        Box::new(BodyVerifier::default()),
    )
    .is_err());
    let mut mutated = checkpoint.as_bytes().to_vec();
    *mutated.last_mut().unwrap() ^= 1;
    assert!(CredentialV2Endpoint::restore_checkpoint(
        &mutated,
        &wrapping_key,
        Side::Allocator,
        &carrier(),
        1,
        1_800_000_800,
        Box::new(BodyVerifier::default()),
    )
    .is_err());
    assert!(CredentialV2Endpoint::restore_checkpoint(
        checkpoint.as_bytes(),
        &wrapping_key,
        Side::Allocator,
        &carrier(),
        2,
        1_800_000_800,
        Box::new(BodyVerifier::default()),
    )
    .is_err());
    assert_eq!(
        CredentialV2Endpoint::restore_checkpoint(
            checkpoint.as_bytes(),
            &wrapping_key,
            Side::Allocator,
            &carrier(),
            1,
            1_800_000_900,
            Box::new(BodyVerifier::default()),
        )
        .unwrap_err(),
        CredentialV2Error::Expired
    );
}

fn endpoints_at_payload() -> (
    CredentialV2Endpoint,
    CredentialV2Endpoint,
    CredentialV2Object,
) {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    allocator.send(&offer).unwrap();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    exchange(&mut claimant, &mut allocator, &approve);
    let preparation = successor(CredentialV2Kind::Preparation, &approve);
    exchange(&mut claimant, &mut allocator, &preparation);
    let comparison = successor(CredentialV2Kind::ComparisonConfirmed, &preparation);
    exchange(&mut allocator, &mut claimant, &comparison);
    let final_approve = successor(CredentialV2Kind::FinalApprove, &comparison);
    exchange(&mut claimant, &mut allocator, &final_approve);
    let payload = successor(CredentialV2Kind::Payload, &final_approve);
    exchange(&mut claimant, &mut allocator, &payload);
    (allocator, claimant, payload)
}

fn endpoints_at_final_approved() -> (
    CredentialV2Endpoint,
    CredentialV2Endpoint,
    CredentialV2Object,
) {
    let (mut allocator, mut claimant) = endpoints();
    let offer = offer();
    allocator.send(&offer).unwrap();
    claimant
        .receive_offer(&offer, &authority(), &mut Parser, &mut IntentVerifier)
        .unwrap();
    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    exchange(&mut claimant, &mut allocator, &approve);
    let preparation = successor(CredentialV2Kind::Preparation, &approve);
    exchange(&mut claimant, &mut allocator, &preparation);
    let comparison = successor(CredentialV2Kind::ComparisonConfirmed, &preparation);
    exchange(&mut allocator, &mut claimant, &comparison);
    let final_approve = successor(CredentialV2Kind::FinalApprove, &comparison);
    exchange(&mut claimant, &mut allocator, &final_approve);
    (allocator, claimant, final_approve)
}

fn exchange(
    sender: &mut CredentialV2Endpoint,
    receiver: &mut CredentialV2Endpoint,
    object: &CredentialV2Object,
) {
    assert_eq!(sender.send(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(receiver.receive(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(sender.phase(), receiver.phase());
}
