//! SPEC-001 REQ-031; SPEC-077 TEST-001 / TEST-006 session export lifetime.
use cbcl_pairing::{
    credential_v2::{
        decode_carrier, encode_carrier, encode_frame, CredentialV2AllocatorBootstrapPhase,
        CredentialV2AllocatorEffect, CredentialV2AllocatorSession,
        CredentialV2AllocatorSessionInput, CredentialV2BodyVerifier, CredentialV2CheckpointNonce,
        CredentialV2Context, CredentialV2Error, CredentialV2Frame, CredentialV2Handoff,
        CredentialV2LogicalBody,
    },
    wire::{encode_server_message, ServerMessage, Side},
};

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 900;
const WRAPPING: [u8; 32] = [0x16; 32];
const PROFILE: [u8; 32] = [0x17; 32];
#[derive(Debug)]
struct NoApplicationCalls;
impl CredentialV2BodyVerifier for NoApplicationCalls {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        panic!("handoff export and recognition must not invoke the application")
    }
}

fn session() -> CredentialV2AllocatorSession {
    CredentialV2AllocatorSession::new(
        CredentialV2AllocatorSessionInput {
            mode: cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
            application_context: "https://a.b/a".into(),
            relay_origin: "https://r".into(),
            mailbox_id: [0x11; 32],
            carrier_ceremony_id: [0x12; 32],
            carrier_nonce: [0x13; 32],
            cpace_secret: [0x14; 16],
            claim_token: [0x15; 16],
            cpace_scalar: [0x18; 32],
            profile_digest: PROFILE,
            expected_allocator_key: Some([0x19; 32]),
            checkpoint_wrapping_key: WRAPPING,
        },
        Box::new(NoApplicationCalls),
    )
    .unwrap()
}

fn receive(
    session: &mut CredentialV2AllocatorSession,
    message: ServerMessage,
    nonce: u8,
) -> Vec<CredentialV2AllocatorEffect> {
    session
        .receive(
            &encode_server_message(&message).unwrap(),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([nonce; 12]),
        )
        .unwrap()
}

fn checkpoint(effects: &[CredentialV2AllocatorEffect]) -> (Vec<u8>, Vec<u8>) {
    let [CredentialV2AllocatorEffect::Checkpoint {
        checkpoint,
        carrier,
        ..
    }] = effects
    else {
        panic!("checkpoint required")
    };
    (checkpoint.as_bytes().to_vec(), carrier.clone())
}

fn restore(
    checkpoint: &[u8],
    carrier: &[u8],
    generation: u64,
    now: u64,
) -> Result<CredentialV2AllocatorSession, CredentialV2Error> {
    CredentialV2AllocatorSession::restore(
        checkpoint,
        &WRAPPING,
        decode_carrier(carrier).unwrap(),
        generation,
        PROFILE,
        now,
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
        [0x39; 32],
        Box::new(NoApplicationCalls),
    )
}

#[test]
fn exact_retained_handoff_is_available_until_claim_admission_before_finished() {
    let mut allocator = session();
    assert!(allocator.handoff_text().unwrap().is_none());
    receive(&mut allocator, ServerMessage::Welcome, 0x21);
    assert!(allocator.handoff_text().unwrap().is_none());
    let effects = receive(
        &mut allocator,
        ServerMessage::AllocatedV2 {
            mailbox_id: [0x11; 32],
            membership_token: [0x20; 32],
            expires_at: EXPIRY,
        },
        0x22,
    );
    let (sealed, public) = checkpoint(&effects);
    allocator.checkpoint_persisted(1).unwrap();
    let text = allocator
        .handoff_text()
        .unwrap()
        .expect("retained C/T can be exported after the committed allocation");
    let handoff: CredentialV2Handoff = text.parse().unwrap();
    assert_eq!(encode_carrier(handoff.carrier()).unwrap(), public);
    assert_eq!(handoff.carrier().relay_expires_at(), EXPIRY);
    assert_eq!(
        handoff.carrier().digest(),
        decode_carrier(&public).unwrap().digest()
    );
    let (carrier, code) = handoff.into_parts();
    let mut presence = code.into_presence();
    assert_eq!(presence.cpace_secret(), &[0x14; 16]);
    assert_eq!(presence.take_claim_token().unwrap().as_bytes(), &[0x15; 16]);

    let restored = restore(&sealed, &public, 1, EXPIRY - 1).unwrap();
    assert_eq!(*restored.handoff_text().unwrap().unwrap(), *text);
    assert!(restore(&sealed, &public, 1, EXPIRY).is_err());
    assert!(restore(&sealed, &public, 1, EXPIRY + 1).is_err());

    let context = CredentialV2Context::derive(&carrier, PROFILE).unwrap();
    let (_, share) = context
        .start_cpace(Side::Claimant, &presence, [0x23; 32])
        .unwrap();
    let frame = CredentialV2Frame::cpace(&share).unwrap();
    let effects = receive(
        &mut allocator,
        ServerMessage::Frame {
            peer_seq: 0,
            body: encode_frame(&frame).unwrap(),
        },
        0x24,
    );
    assert_eq!(
        allocator.bootstrap_phase(),
        Some(CredentialV2AllocatorBootstrapPhase::ShareSent)
    );
    assert!(allocator.transcript_hash().is_none());
    assert!(allocator.handoff_text().unwrap().is_none());
    let (claimed, public) = checkpoint(&effects);
    allocator.checkpoint_persisted(2).unwrap();
    assert!(allocator.handoff_text().unwrap().is_none());
    let restored = restore(&claimed, &public, 2, NOW).unwrap();
    assert!(restored.handoff_text().unwrap().is_none());
    assert!(restored.transcript_hash().is_none());
}

#[test]
fn closed_or_failed_session_with_retained_t_exports_nothing() {
    for closed in [true, false] {
        let mut allocator = session();
        receive(&mut allocator, ServerMessage::Welcome, 0x31);
        receive(
            &mut allocator,
            ServerMessage::AllocatedV2 {
                mailbox_id: [0x11; 32],
                membership_token: [0x20; 32],
                expires_at: EXPIRY,
            },
            0x32,
        );
        allocator.checkpoint_persisted(1).unwrap();
        assert!(allocator.handoff_text().unwrap().is_some());
        let result = allocator.receive(
            &encode_server_message(&if closed {
                ServerMessage::Closed(cbcl_pairing::wire::CloseReason::Closed)
            } else {
                ServerMessage::Welcome
            })
            .unwrap(),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x33; 12]),
        );
        if !closed {
            assert!(result.is_err());
        }
        assert!(allocator.handoff_text().unwrap().is_none());
    }
}
