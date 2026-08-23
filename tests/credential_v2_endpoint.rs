//! SPEC-001 TEST-061 and TEST-064 Red Gate: credential/v2 choreography.

use cbcl_pairing::{
    credential_v2::{
        credential_v2_intent_digest, CredentialV2AccountProvenance, CredentialV2Advance,
        CredentialV2BodyVerifier, CredentialV2DeviceBinding, CredentialV2Endpoint,
        CredentialV2Error, CredentialV2IntentAuthority, CredentialV2IntentClaims,
        CredentialV2IntentInput, CredentialV2IntentVerifier, CredentialV2Kind,
        CredentialV2LogicalBody, CredentialV2Object, CredentialV2OfferParser, CredentialV2Phase,
        CredentialV2TofuState, CredentialV2Transition,
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
        CredentialV2Endpoint::new(Side::Allocator, CEREMONY, Box::new(BodyVerifier::default())),
        CredentialV2Endpoint::new(Side::Claimant, CEREMONY, Box::new(BodyVerifier::default())),
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
        CEREMONY,
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

fn exchange(
    sender: &mut CredentialV2Endpoint,
    receiver: &mut CredentialV2Endpoint,
    object: &CredentialV2Object,
) {
    assert_eq!(sender.send(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(receiver.receive(object), Ok(CredentialV2Advance::Advanced));
    assert_eq!(sender.phase(), receiver.phase());
}
