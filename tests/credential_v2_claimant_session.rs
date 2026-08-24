//! SPEC-001 CON-030 claimant bootstrap stays restart-abandonable.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        credential_v2_intent_digest, decode_frame, encode_frame, CredentialV2AccountProvenance,
        CredentialV2Advance, CredentialV2BodyVerifier, CredentialV2Carrier,
        CredentialV2CarrierInput, CredentialV2CheckpointNonce, CredentialV2ClaimantEffect,
        CredentialV2ClaimantOfferVerifier, CredentialV2ClaimantSession,
        CredentialV2ClaimantSessionInput, CredentialV2Context, CredentialV2DeviceBinding,
        CredentialV2Endpoint, CredentialV2Error, CredentialV2Frame, CredentialV2IntentAuthority,
        CredentialV2IntentClaims, CredentialV2IntentInput, CredentialV2IntentVerifier,
        CredentialV2Kind, CredentialV2LogicalBody, CredentialV2Object, CredentialV2OfferParser,
        CredentialV2Phase, CredentialV2Presence, CredentialV2PresenceCode, CredentialV2TofuState,
        CredentialV2Transition, PendingCredentialV2Channel,
    },
    wire::{
        claim_commitment, decode_client_message, encode_server_message, ClaimToken, ClientMessage,
        ServerMessage, Side,
    },
};
use ciborium::Value;
use sha2::Digest as _;

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 900;
const MAILBOX: [u8; 32] = [0x61; 32];
const CPACE_SECRET: [u8; 16] = [0x62; 16];
const CLAIM_TOKEN: [u8; 16] = [0x63; 16];
const PROFILE_DIGEST: [u8; 32] = [0x64; 32];
const MEMBERSHIP: [u8; 32] = [0x65; 32];
const CEREMONY: [u8; 32] = [0x66; 32];
const OFFER_CORE: [u8; 32] = [0x74; 32];

#[derive(Debug)]
struct AcceptBodies;

impl CredentialV2BodyVerifier for AcceptBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Ok(())
    }
}

fn claims() -> CredentialV2IntentClaims {
    CredentialV2IntentClaims::new(
        "https://chat.anuna.io/selfsame/v2",
        "https://chat.anuna.io",
        "https://chat.anuna.io:9443",
        CEREMONY,
        CredentialV2AccountProvenance::new([0x75; 32], [0x76; 32]),
        vec!["https://chat.anuna.io/selfsame/v2#chat-send".into()],
        CredentialV2DeviceBinding::new(format!("did:key:z6Mk{}", "1".repeat(44)), [0x77; 32])
            .unwrap(),
        CredentialV2Transition::NoTransition,
        OFFER_CORE,
    )
    .unwrap()
}

#[derive(Debug)]
struct OfferParser;

impl CredentialV2OfferParser for OfferParser {
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

#[derive(Debug)]
struct TestOfferVerifier;

impl CredentialV2ClaimantOfferVerifier for TestOfferVerifier {
    fn verify_offer(
        &mut self,
        endpoint: &mut CredentialV2Endpoint,
        object: &CredentialV2Object,
        _: u64,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        endpoint.receive_offer(
            object,
            &CredentialV2IntentAuthority::new(claims(), CredentialV2TofuState::NewPair)?,
            &mut OfferParser,
            &mut IntentVerifier,
        )
    }
}

fn offer() -> CredentialV2Object {
    CredentialV2Object::new(
        CredentialV2Kind::Offer,
        credential_v2_intent_digest(OFFER_CORE),
        vec![0x81],
    )
    .unwrap()
}

fn successor(kind: CredentialV2Kind, predecessor: &CredentialV2Object) -> CredentialV2Object {
    let body = cbor2::to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("carrierCeremonyId".into()),
            Value::Bytes(CEREMONY.to_vec()),
        ),
        (
            Value::Text("predecessorDigest".into()),
            Value::Bytes(predecessor.content_hash().to_vec()),
        ),
        (Value::Text("fixture".into()), Value::Integer(1.into())),
    ]))
    .unwrap();
    CredentialV2Object::new(kind, *predecessor.intent_digest(), body).unwrap()
}

fn receipt(predecessor: &CredentialV2Object) -> CredentialV2Object {
    let final_status_jws = "e30.e30.AA";
    let final_status_digest = sha2::Sha256::digest(final_status_jws.as_bytes());
    let body = cbor2::to_canonical_vec(&Value::Map(vec![
        (
            Value::Text("carrierCeremonyId".into()),
            Value::Bytes(CEREMONY.to_vec()),
        ),
        (
            Value::Text("predecessorDigest".into()),
            Value::Bytes(predecessor.content_hash().to_vec()),
        ),
        (
            Value::Text("finalStatusJws".into()),
            Value::Text(final_status_jws.into()),
        ),
        (
            Value::Text("finalStatusDigest".into()),
            Value::Bytes(final_status_digest.to_vec()),
        ),
    ]))
    .unwrap();
    CredentialV2Object::new(
        CredentialV2Kind::Receipt,
        *predecessor.intent_digest(),
        body,
    )
    .unwrap()
}

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: MAILBOX,
        carrier_ceremony_id: CEREMONY,
        carrier_nonce: [0x67; 32],
        claim_commitment: claim_commitment(MAILBOX, &ClaimToken::new(CLAIM_TOKEN)),
        relay_expires_at: EXPIRY,
        expected_allocator_key: Some([0x68; 32]),
    })
    .unwrap()
}

fn server(message: ServerMessage) -> Vec<u8> {
    encode_server_message(&message).unwrap()
}

fn sent(effects: &[CredentialV2ClaimantEffect]) -> Vec<ClientMessage> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            CredentialV2ClaimantEffect::Send(bytes) => Some(decode_client_message(bytes).unwrap()),
            _ => None,
        })
        .collect()
}

#[test]
fn claimant_completes_claim_cpace_and_finished_without_a_preapproval_checkpoint() {
    let recognised_carrier = carrier();
    let mut claimant = CredentialV2ClaimantSession::new(
        CredentialV2ClaimantSessionInput {
            carrier: recognised_carrier.clone(),
            presence_code: CredentialV2PresenceCode::new(CPACE_SECRET, CLAIM_TOKEN),
            cpace_scalar: [0x69; 32],
            profile_digest: PROFILE_DIGEST,
        },
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(
        decode_client_message(&claimant.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );

    let claim = claimant
        .receive(&server(ServerMessage::Welcome), NOW)
        .unwrap();
    assert_eq!(
        sent(&claim),
        vec![ClientMessage::ClaimV2 {
            mailbox_id: MAILBOX,
            claim_token: ClaimToken::new(CLAIM_TOKEN),
        }],
    );

    let claimant_share_effects = claimant
        .receive(
            &server(ServerMessage::ClaimedV2 {
                mailbox_id: MAILBOX,
                membership_token: MEMBERSHIP,
                expires_at: EXPIRY,
            }),
            NOW,
        )
        .unwrap();
    let claimant_share_commands = sent(&claimant_share_effects);
    let [ClientMessage::Put {
        seq: 0,
        body: claimant_share,
    }] = claimant_share_commands.as_slice()
    else {
        panic!("claimant CPace share must be exact relay sequence zero")
    };
    let claimant_share = decode_frame(claimant_share).unwrap();

    let context = CredentialV2Context::derive(&recognised_carrier, PROFILE_DIGEST).unwrap();
    let allocator_presence = CredentialV2Presence::new(CPACE_SECRET, CLAIM_TOKEN);
    let (allocator_state, allocator_message) = context
        .start_cpace(Side::Allocator, &allocator_presence, [0x73; 32])
        .unwrap();
    let allocator_share = CredentialV2Frame::cpace(&allocator_message).unwrap();

    assert!(claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 0 }), NOW)
        .unwrap()
        .is_empty());

    let finished_effects = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 0,
                body: encode_frame(&allocator_share).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    let commands = sent(&finished_effects);
    assert_eq!(commands[0], ClientMessage::Ack { peer_seq: 0 });
    let ClientMessage::Put {
        seq: 1,
        body: claimant_finished,
    } = &commands[1]
    else {
        panic!("claimant Finished must be exact relay sequence one")
    };
    let claimant_finished = decode_frame(claimant_finished).unwrap();

    let allocator_isk = cpace::finish(
        allocator_state,
        claimant_share
            .cpace_message()
            .expect("claimant CPace share"),
    )
    .unwrap();
    let allocator_pending = PendingCredentialV2Channel::new(
        Side::Allocator,
        allocator_isk,
        context.public_context(),
        &encode_frame(&allocator_share).unwrap(),
        &encode_frame(&claimant_share).unwrap(),
    )
    .unwrap();
    let allocator_finished = allocator_pending.local_finished_frame();

    assert!(claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 1 }), NOW)
        .unwrap()
        .is_empty());
    let established = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 1,
                body: encode_frame(&allocator_finished).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        established.as_slice(),
        [CredentialV2ClaimantEffect::Send(_), CredentialV2ClaimantEffect::Established {
            transcript_hash
        }] if transcript_hash.len() == 64
    ));
    assert_eq!(sent(&established), vec![ClientMessage::Ack { peer_seq: 1 }]);

    claimant
        .authorise_authenticated_profile(Box::new(TestOfferVerifier))
        .unwrap();
    let receipt_recovery_commitment = claimant.receipt_recovery_commitment().unwrap();
    assert_ne!(receipt_recovery_commitment, [0_u8; 32]);
    assert_eq!(
        claimant.receipt_recovery_commitment().unwrap(),
        receipt_recovery_commitment
    );
    assert!(matches!(
        claimant.authorise_authenticated_profile(Box::new(TestOfferVerifier)),
        Err(CredentialV2Error::Phase)
    ));

    let mut allocator_channel = allocator_pending.confirm(&claimant_finished).unwrap();
    let offer = offer();
    let offer_frame = allocator_channel.seal(offer.as_bytes()).unwrap();
    let displayed = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 2,
                body: encode_frame(&offer_frame).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        displayed.as_slice(),
        [
            CredentialV2ClaimantEffect::Send(_),
            CredentialV2ClaimantEffect::DisplayIntent(_)
        ]
    ));

    let approve = successor(CredentialV2Kind::IntentApprove, &offer);
    let approve_effects = claimant.prepare_application_object(&approve).unwrap();
    let approve_commands = sent(&approve_effects);
    let [ClientMessage::Put {
        seq: 2,
        body: sealed_approve,
    }] = approve_commands.as_slice()
    else {
        panic!("preliminary approval must be the exact next memory-only frame")
    };
    assert_eq!(
        allocator_channel
            .open(&decode_frame(sealed_approve).unwrap())
            .unwrap(),
        approve.as_bytes()
    );
    claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 2 }), NOW)
        .unwrap();

    let preparation = successor(CredentialV2Kind::Preparation, &approve);
    let preparation_effects = claimant.prepare_application_object(&preparation).unwrap();
    let preparation_commands = sent(&preparation_effects);
    let [ClientMessage::Put {
        seq: 3,
        body: sealed_preparation,
    }] = preparation_commands.as_slice()
    else {
        panic!("preparation must remain an uncheckpointed memory-only frame")
    };
    assert_eq!(
        allocator_channel
            .open(&decode_frame(sealed_preparation).unwrap())
            .unwrap(),
        preparation.as_bytes()
    );
    claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 3 }), NOW)
        .unwrap();

    let comparison = successor(CredentialV2Kind::ComparisonConfirmed, &preparation);
    let comparison_frame = allocator_channel.seal(comparison.as_bytes()).unwrap();
    let compared = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 3,
                body: encode_frame(&comparison_frame).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        compared.as_slice(),
        [CredentialV2ClaimantEffect::Send(_), CredentialV2ClaimantEffect::ReceivedObject {
            object
        }] if object == &comparison
    ));

    let final_approve = successor(CredentialV2Kind::FinalApprove, &comparison);
    assert!(matches!(
        claimant.prepare_application_object(&final_approve),
        Err(CredentialV2Error::Phase)
    ));

    let wrapping_key = [0x78; 32];
    let checkpoint_effects = claimant
        .prepare_final_approval(
            &final_approve,
            &wrapping_key,
            CredentialV2CheckpointNonce::from_csprng([0x79; 12]),
            NOW,
        )
        .unwrap();
    let [CredentialV2ClaimantEffect::Checkpoint {
        generation: 1,
        checkpoint,
    }] = checkpoint_effects.as_slice()
    else {
        panic!("final approval must expose only its first durable checkpoint")
    };
    let restored = CredentialV2Endpoint::restore_checkpoint(
        checkpoint.as_bytes(),
        &wrapping_key,
        Side::Claimant,
        &recognised_carrier,
        1,
        NOW,
        Box::new(AcceptBodies),
    )
    .unwrap();
    let (restored_endpoint, _, restored_relay) = restored.into_parts();
    assert_eq!(restored_endpoint.phase(), CredentialV2Phase::FinalApproved);
    assert!(restored_relay.cached_outbound_frame().is_some());
    assert!(claimant.receive(&server(ServerMessage::Pong), NOW).is_err());
    assert!(matches!(
        claimant.checkpoint_persisted(2),
        Err(CredentialV2Error::Counter)
    ));

    let released = claimant.checkpoint_persisted(1).unwrap();
    let released_commands = sent(&released);
    let [ClientMessage::Put {
        seq: 4,
        body: sealed_final_approve,
    }] = released_commands.as_slice()
    else {
        panic!("only durable final approval can release its exact cached frame")
    };
    assert_eq!(
        allocator_channel
            .open(&decode_frame(sealed_final_approve).unwrap())
            .unwrap(),
        final_approve.as_bytes()
    );
    assert!(matches!(
        claimant.checkpoint_persisted(1),
        Err(CredentialV2Error::Counter)
    ));

    assert!(claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 4 }), NOW)
        .is_err());
    let ack_checkpoint = claimant
        .receive_durable(
            &server(ServerMessage::Acknowledged { seq: 4 }),
            NOW,
            &wrapping_key,
            CredentialV2CheckpointNonce::from_csprng([0x7a; 12]),
        )
        .unwrap();
    assert!(matches!(
        ack_checkpoint.as_slice(),
        [CredentialV2ClaimantEffect::Checkpoint { generation: 2, .. }]
    ));
    assert!(claimant.checkpoint_persisted(2).unwrap().is_empty());

    let payload = successor(CredentialV2Kind::Payload, &final_approve);
    let payload_checkpoint = claimant
        .prepare_payload(
            &payload,
            &wrapping_key,
            CredentialV2CheckpointNonce::from_csprng([0x7b; 12]),
            NOW,
        )
        .unwrap();
    let [CredentialV2ClaimantEffect::Checkpoint {
        generation: 3,
        checkpoint,
    }] = payload_checkpoint.as_slice()
    else {
        panic!("payload send must first expose its null-expiry checkpoint")
    };
    let restored = CredentialV2Endpoint::restore_checkpoint(
        checkpoint.as_bytes(),
        &wrapping_key,
        Side::Claimant,
        &recognised_carrier,
        3,
        EXPIRY + 1,
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(
        restored.into_parts().0.phase(),
        CredentialV2Phase::PayloadSent
    );
    let mut recovered = CredentialV2ClaimantSession::restore(
        checkpoint.as_bytes(),
        &wrapping_key,
        recognised_carrier.clone(),
        3,
        EXPIRY + 1,
        Box::new(AcceptBodies),
    )
    .unwrap();
    let recovered_commitment = recovered
        .with_receipt_recovery_token(|token| {
            let mut digest = sha2::Sha256::new();
            digest.update(b"selfsame credential/v2 receipt recovery commitment v1\0");
            digest.update(token);
            digest.update(recognised_carrier.carrier_ceremony_id());
            digest.update(recognised_carrier.application_context().as_bytes());
            <[u8; 32]>::from(digest.finalize())
        })
        .unwrap();
    assert_eq!(
        recovered_commitment,
        recovered.receipt_recovery_commitment().unwrap(),
        "a restored payload checkpoint must reproduce the exact secret token without exposing it through a browser adapter",
    );
    let recovered_commands = sent(&recovered.resume_cached_frame().unwrap());
    assert!(matches!(
        recovered_commands.as_slice(),
        [ClientMessage::Put { seq: 5, .. }]
    ));

    let payload_release = claimant.checkpoint_persisted(3).unwrap();
    let payload_commands = sent(&payload_release);
    let [ClientMessage::Put {
        seq: 5,
        body: sealed_payload,
    }] = payload_commands.as_slice()
    else {
        panic!("only the retained payload checkpoint may release payload")
    };
    assert_eq!(
        allocator_channel
            .open(&decode_frame(sealed_payload).unwrap())
            .unwrap(),
        payload.as_bytes()
    );

    let mut direct_recovery = CredentialV2ClaimantSession::restore(
        checkpoint.as_bytes(),
        &wrapping_key,
        recognised_carrier.clone(),
        3,
        EXPIRY + 1,
        Box::new(AcceptBodies),
    )
    .unwrap();
    let recovered_receipt = direct_recovery
        .authenticate_recovered_receipt_object(receipt(&payload))
        .unwrap();
    assert!(direct_recovery
        .commit_recovered_receipt(recovered_receipt)
        .unwrap()
        .is_empty());

    let payload_ack = claimant
        .receive_durable(
            &server(ServerMessage::Acknowledged { seq: 5 }),
            NOW,
            &wrapping_key,
            CredentialV2CheckpointNonce::from_csprng([0x7c; 12]),
        )
        .unwrap();
    assert!(matches!(
        payload_ack.as_slice(),
        [CredentialV2ClaimantEffect::Checkpoint { generation: 4, .. }]
    ));
    assert!(claimant.checkpoint_persisted(4).unwrap().is_empty());

    let receipt = receipt(&payload);
    let receipt_frame = allocator_channel.seal(receipt.as_bytes()).unwrap();
    let recovered = claimant
        .receive_recovered_receipt(&server(ServerMessage::Frame {
            peer_seq: 4,
            body: encode_frame(&receipt_frame).unwrap(),
        }))
        .unwrap();
    assert_eq!(recovered.object(), &receipt);
    assert!(claimant.has_pending_recovered_receipt());

    // Merely authenticating and exposing the receipt cannot acknowledge it.
    // The wallet first verifies the signed final status, live WebFinger, and
    // its durable installed-slot transition, then commits this one-use edge.
    let committed = claimant.commit_recovered_receipt(recovered).unwrap();
    assert_eq!(sent(&committed), vec![ClientMessage::Ack { peer_seq: 4 }]);
    assert!(!claimant.has_pending_recovered_receipt());
}
