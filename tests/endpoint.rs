//! SPEC-072 endpoint reducer Red Gate (TEST-009, TEST-021, TEST-022).

use cbcl_core::message::CausedBy;
use cbcl_pairing::{
    cbcl_protocol::{
        build_bootstrap_control, build_session_control, ceremony_id, BootstrapMonitor,
        BootstrapPerformative, CeremonySigningKey, PairingRole, ProtocolVerdict, SessionMonitor,
        SessionPerformative,
    },
    channel::PendingChannel,
    context::PairingContext,
    cpace,
    endpoint::{
        BindOutcome, EndpointEffect, EndpointReducer, InvitationRecord, InvitationStatus,
        ReducerError, TerminalReason,
    },
    profile::{
        ApplicationProfile, AuthorisedGrant, SyntheticGrant, SyntheticIntentClaims,
        SyntheticProfile, SYNTHETIC_ACTION, SYNTHETIC_APPLICATION, SYNTHETIC_PAYLOAD,
    },
    wire::{
        decode_invitation, decode_pairing_intent, decode_sealed_plaintext, encode_channel_frame,
        encode_cpace_message, encode_invitation, encode_pairing_decision, encode_sealed_plaintext,
        ApplicationPayload, ChannelFrame, Decision, Invitation, Locator, PairingDecision,
        PairingIntent, SealedPlaintext, Side,
    },
};
use sha2::{Digest, Sha256};

const MAILBOX_ID: [u8; 32] = [0x55; 32];

struct Materials {
    invitation: Vec<u8>,
    allocator_key: CeremonySigningKey,
    claimant_key: CeremonySigningKey,
    allocator_monitor: BootstrapMonitor,
    claimant_monitor: BootstrapMonitor,
    allocator_pending: PendingChannel,
    claimant_pending: PendingChannel,
    allocator_hash: String,
    claimant_hash: String,
    allocator_control: Vec<u8>,
    claimant_control: Vec<u8>,
    allocator_body: Vec<u8>,
    claimant_body: Vec<u8>,
    allocator_frame_bytes: Vec<u8>,
    claimant_frame_bytes: Vec<u8>,
}

fn invitation() -> Invitation {
    Invitation {
        application: "example.test/synthetic/v1".into(),
        relay_origin: "https://relay.example.test".into(),
        locator: Locator::Direct(MAILBOX_ID),
        secret: vec![0x31; 16],
        expected_allocator_key: None,
        expected_claimant_key: None,
    }
}

fn invitation_bytes() -> Vec<u8> {
    encode_invitation(&invitation()).expect("invitation")
}

fn materials() -> Materials {
    let invitation_value = invitation();
    let invitation = encode_invitation(&invitation_value).expect("invitation");
    let allocator_key = CeremonySigningKey::from_secret([0x11; 32]).expect("allocator key");
    let claimant_key = CeremonySigningKey::from_secret([0x22; 32]).expect("claimant key");
    let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&invitation);
    let (allocator_state, allocator_message) =
        cpace::start_pairing(Side::Allocator, &invitation_value, MAILBOX_ID, [0x41; 32])
            .expect("allocator CPace");
    let (claimant_state, claimant_message) =
        cpace::start_pairing(Side::Claimant, &invitation_value, MAILBOX_ID, [0x42; 32])
            .expect("claimant CPace");
    let allocator_isk = cpace::finish(allocator_state, &claimant_message).expect("allocator ISK");
    let claimant_isk = cpace::finish(claimant_state, &allocator_message).expect("claimant ISK");

    let allocator_body = encode_cpace_message(&allocator_message).expect("allocator message");
    let claimant_body = encode_cpace_message(&claimant_message).expect("claimant message");
    let allocator_control = build_bootstrap_control(
        &allocator_key,
        BootstrapPerformative::CpaceA,
        &ceremony,
        &allocator_body,
        CausedBy::Begin,
    )
    .expect("allocator control");
    let claimant_control = build_bootstrap_control(
        &claimant_key,
        BootstrapPerformative::CpaceB,
        &ceremony,
        &claimant_body,
        CausedBy::Begin,
    )
    .expect("claimant control");
    let allocator_frame = ChannelFrame::Cpace {
        side: Side::Allocator,
        control: allocator_control.clone(),
        message: allocator_body.clone(),
    };
    let claimant_frame = ChannelFrame::Cpace {
        side: Side::Claimant,
        control: claimant_control.clone(),
        message: claimant_body.clone(),
    };
    let allocator_frame_bytes = encode_channel_frame(&allocator_frame).expect("allocator frame");
    let claimant_frame_bytes = encode_channel_frame(&claimant_frame).expect("claimant frame");

    let mut allocator_monitor = BootstrapMonitor::new(&invitation).expect("allocator monitor");
    let mut claimant_monitor = BootstrapMonitor::new(&invitation).expect("claimant monitor");
    let allocator_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .expect("allocator local")
        .content_hash()
        .to_owned();
    let claimant_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .expect("allocator peer")
        .content_hash()
        .to_owned();
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .expect("claimant peer");
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .expect("claimant local");

    let allocator_pending = PendingChannel::new_pairing(
        Side::Allocator,
        allocator_isk,
        &invitation_value,
        MAILBOX_ID,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .expect("allocator pending");
    let claimant_pending = PendingChannel::new_pairing(
        Side::Claimant,
        claimant_isk,
        &invitation_value,
        MAILBOX_ID,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .expect("claimant pending");

    Materials {
        invitation,
        allocator_key,
        claimant_key,
        allocator_monitor,
        claimant_monitor,
        allocator_pending,
        claimant_pending,
        allocator_hash,
        claimant_hash,
        allocator_control,
        claimant_control,
        allocator_body,
        claimant_body,
        allocator_frame_bytes,
        claimant_frame_bytes,
    }
}

fn bound_record(invitation: &[u8], peer_frame: &[u8]) -> InvitationRecord {
    let invitation_value = decode_invitation(invitation).expect("invitation");
    let context = PairingContext::derive(&invitation_value, MAILBOX_ID).expect("context");
    let mut record = InvitationRecord::new(invitation);
    assert_eq!(
        record
            .bind(MAILBOX_ID, peer_frame, context.channel_context())
            .expect("bind"),
        BindOutcome::Bound
    );
    record
}

fn reducer_pair() -> (EndpointReducer, EndpointReducer) {
    let m = materials();
    let allocator_record = bound_record(&m.invitation, &m.claimant_frame_bytes);
    let claimant_record = bound_record(&m.invitation, &m.allocator_frame_bytes);
    let allocator = EndpointReducer::new(
        Side::Allocator,
        &m.invitation,
        allocator_record,
        m.allocator_key,
        m.allocator_monitor,
        m.allocator_pending,
        m.allocator_hash.clone(),
        m.claimant_hash.clone(),
        Box::new(SyntheticProfile::new(true)),
    )
    .expect("allocator reducer");
    let claimant = EndpointReducer::new(
        Side::Claimant,
        &m.invitation,
        claimant_record,
        m.claimant_key,
        m.claimant_monitor,
        m.claimant_pending,
        m.allocator_hash,
        m.claimant_hash,
        Box::new(SyntheticProfile::new(true)),
    )
    .expect("claimant reducer");
    (allocator, claimant)
}

fn extract_frame(effects: &[EndpointEffect]) -> ChannelFrame {
    effects
        .iter()
        .find_map(|effect| match effect {
            EndpointEffect::SendFrame(frame) => Some(frame.clone()),
            _ => None,
        })
        .expect("send-frame effect")
}

fn confirmed_pair() -> (EndpointReducer, EndpointReducer) {
    let (mut allocator, mut claimant) = reducer_pair();
    let allocator_finished = allocator
        .local_finished_frame()
        .expect("allocator finished")
        .expect("allocator Finished is causally valid");
    let claimant_finished = claimant
        .local_finished_frame()
        .expect("claimant finished")
        .expect("claimant Finished is causally valid");
    let claimant_effects = claimant
        .receive_frame(&allocator_finished)
        .expect("claimant confirms");
    assert!(claimant_effects.is_empty());
    let allocator_effects = allocator
        .receive_frame(&claimant_finished)
        .expect("allocator confirms and opens roles");
    let opener = extract_frame(&allocator_effects);
    assert!(allocator.session_ready());
    assert!(!claimant.session_ready());
    assert!(claimant
        .receive_frame(&opener)
        .expect("claimant admits opener")
        .is_empty());
    assert!(claimant.session_ready());
    (allocator, claimant)
}

fn intent() -> PairingIntent {
    let claims = SyntheticIntentClaims {
        subject: "synthetic subject".into(),
        audience: "synthetic audience".into(),
    }
    .encode()
    .expect("synthetic claims");
    PairingIntent {
        application: SYNTHETIC_APPLICATION.into(),
        action: SYNTHETIC_ACTION.into(),
        allocator_claim: claims.0,
        claimant_claim: claims.1,
        authority_summary: "test authority".into(),
        intent_nonce: [0x77; 32],
    }
}

fn displayed_intent(intent: &PairingIntent) -> cbcl_pairing::profile::DisplayIntent {
    SyntheticProfile::new(true)
        .recognise_intent(intent)
        .expect("profile intent")
        .into_parts()
        .0
}

fn synthetic_grant_body() -> Vec<u8> {
    SyntheticGrant {
        subject: "synthetic subject".into(),
        audience: "synthetic audience".into(),
        grant: b"opaque synthetic grant".to_vec(),
    }
    .encode()
    .expect("synthetic grant")
}

fn synthetic_payload(intent_digest: [u8; 32]) -> ApplicationPayload {
    ApplicationPayload {
        intent_digest,
        payload_type: SYNTHETIC_PAYLOAD.into(),
        body: synthetic_grant_body(),
    }
}

#[test]
fn invitation_is_bound_before_the_first_guess_and_only_exact_resume_survives() {
    let invitation = invitation_bytes();
    let mut record = InvitationRecord::new(&invitation);
    assert_eq!(record.status(), InvitationStatus::Unused);
    assert_eq!(
        record
            .bind(MAILBOX_ID, b"peer-frame", b"public-context")
            .expect("first bind"),
        BindOutcome::Bound
    );
    assert_eq!(record.status(), InvitationStatus::Bound);
    assert_eq!(
        record
            .bind(MAILBOX_ID, b"peer-frame", b"public-context")
            .expect("exact resume"),
        BindOutcome::Resumed
    );
    assert_eq!(
        record
            .bind(MAILBOX_ID, b"alternate-peer-frame", b"public-context")
            .unwrap_err(),
        ReducerError::Invitation
    );
    assert_eq!(record.status(), InvitationStatus::Spent);
}

#[test]
fn test_021_unknown_finished_has_no_crypto_or_role_cast_effect() {
    let m = materials();
    let mut incomplete = BootstrapMonitor::new(&m.invitation).expect("monitor");
    incomplete
        .admit(
            BootstrapPerformative::CpaceA,
            &m.allocator_control,
            &m.allocator_body,
        )
        .expect("only allocator CPace");
    let record = bound_record(&m.invitation, &m.claimant_frame_bytes);
    let mut endpoint = EndpointReducer::new(
        Side::Allocator,
        &m.invitation,
        record,
        m.allocator_key,
        incomplete,
        m.allocator_pending,
        m.allocator_hash,
        m.claimant_hash,
        Box::new(SyntheticProfile::new(true)),
    )
    .expect("endpoint");

    assert_eq!(endpoint.local_finished_frame().expect("Unknown"), None);
    assert!(!endpoint.session_ready());
    assert!(!endpoint.secrets_erased());
    assert_eq!(endpoint.terminal_reason(), None);
    assert_eq!(
        endpoint
            .admit_bootstrap_control(
                BootstrapPerformative::CpaceB,
                &m.claimant_control,
                &m.claimant_body,
            )
            .expect("missing predecessor"),
        ProtocolVerdict::Valid
    );
    assert!(endpoint.local_finished_frame().expect("retry").is_some());
}

#[test]
fn test_009_decline_erases_both_endpoints_and_releases_no_payload() {
    let (mut allocator, mut claimant) = confirmed_pair();
    let intent = intent();
    let display = displayed_intent(&intent);
    let intent_frame = allocator.send_intent(&intent).expect("send intent");
    assert_eq!(
        claimant
            .receive_frame(&intent_frame)
            .expect("receive intent"),
        vec![EndpointEffect::DisplayIntent(display)]
    );
    let decline_effects = claimant.decide(Decision::Decline).expect("decline");
    let decline_frame = extract_frame(&decline_effects);
    assert!(decline_effects.contains(&EndpointEffect::CloseMailbox));
    assert!(!decline_effects
        .iter()
        .any(|effect| matches!(effect, EndpointEffect::DeliverGrant(_))));
    assert_eq!(claimant.terminal_reason(), Some(TerminalReason::Declined));
    assert!(claimant.secrets_erased());
    assert_eq!(claimant.delivered_payloads(), 0);
    assert_eq!(claimant.decide(Decision::Decline), Ok(Vec::new()));

    let allocator_effects = allocator
        .receive_frame(&decline_frame)
        .expect("receive decline");
    assert_eq!(allocator_effects, vec![EndpointEffect::CloseMailbox]);
    assert_eq!(allocator.terminal_reason(), Some(TerminalReason::Declined));
    assert!(allocator.secrets_erased());
    assert_eq!(allocator.delivered_payloads(), 0);
    assert_eq!(allocator.invitation_status(), InvitationStatus::Spent);
    assert_eq!(allocator.receive_frame(&decline_frame), Ok(Vec::new()));
}

#[test]
fn test_022_decision_is_atomic_replay_idempotent_and_conflict_terminal() {
    let (mut allocator, mut claimant) = confirmed_pair();
    let intent_frame = allocator.send_intent(&intent()).expect("intent");
    claimant
        .receive_frame(&intent_frame)
        .expect("display intent");

    let approval = claimant.decide(Decision::Approve).expect("approve");
    assert_eq!(claimant.decide(Decision::Approve), Ok(Vec::new()));
    assert_eq!(
        claimant.decide(Decision::Decline),
        Err(ReducerError::DecisionConflict)
    );
    assert_eq!(
        claimant.terminal_reason(),
        Some(TerminalReason::DecisionConflict)
    );
    assert!(claimant.secrets_erased());
    assert_eq!(claimant.delivered_payloads(), 0);

    // The already-produced approval remains individually valid to the peer.
    let approval_frame = extract_frame(&approval);
    assert!(allocator
        .receive_frame(&approval_frame)
        .expect("approval")
        .is_empty());
}

#[test]
fn test_012_approved_payload_is_released_once_and_only_for_the_intent_digest() {
    let (mut allocator, mut claimant) = confirmed_pair();
    let intent_frame = allocator.send_intent(&intent()).expect("intent");
    claimant
        .receive_frame(&intent_frame)
        .expect("intent receive");
    let approval = claimant.decide(Decision::Approve).expect("approval");
    allocator
        .receive_frame(&extract_frame(&approval))
        .expect("approval receive");
    let digest = allocator.intent_digest().expect("accepted intent digest");
    let payload = ApplicationPayload {
        intent_digest: digest,
        payload_type: SYNTHETIC_PAYLOAD.into(),
        body: synthetic_grant_body(),
    };
    let frame = allocator.send_payload(&payload).expect("payload");
    assert_eq!(
        claimant.receive_frame(&frame).expect("payload receive"),
        vec![EndpointEffect::DeliverGrant(AuthorisedGrant {
            application: SYNTHETIC_APPLICATION.into(),
            payload_type: SYNTHETIC_PAYLOAD.into(),
            body: payload.body.clone(),
        })]
    );
    assert_eq!(claimant.delivered_payloads(), 1);
    assert_eq!(claimant.profile_verifications(), 1);

    let wrong = ApplicationPayload {
        intent_digest: [0x99; 32],
        payload_type: SYNTHETIC_PAYLOAD.into(),
        body: synthetic_grant_body(),
    };
    assert_eq!(
        allocator.send_payload(&wrong),
        Err(ReducerError::IntentDigest)
    );
}

#[test]
fn test_019_authorization_cannot_bypass_pairing_gates() {
    let (allocator, mut claimant) = reducer_pair();
    let premature = ChannelFrame::Sealed {
        direction: cbcl_pairing::wire::Direction::AllocatorToClaimant,
        counter: 0,
        ciphertext: vec![0; 17],
    };
    assert_eq!(claimant.receive_frame(&premature), Err(ReducerError::Phase));
    assert_eq!(claimant.invitation_status(), InvitationStatus::Bound);
    assert_eq!(claimant.profile_verifications(), 0);
    assert!(!claimant.session_ready());
    drop(allocator);

    let (mut allocator, mut claimant) = confirmed_pair();
    let intent_frame = allocator.send_intent(&intent()).expect("intent");
    claimant
        .receive_frame(&intent_frame)
        .expect("recognised display");
    let digest = allocator.intent_digest().expect("intent digest");
    assert_eq!(
        allocator.send_payload(&synthetic_payload(digest)),
        Err(ReducerError::Phase)
    );
    assert_eq!(allocator.profile_verifications(), 0);
    assert_eq!(claimant.profile_verifications(), 0);

    let decline = claimant.decide(Decision::Decline).expect("decline");
    allocator
        .receive_frame(&extract_frame(&decline))
        .expect("decline received");
    assert_eq!(
        allocator.send_payload(&synthetic_payload(digest)),
        Err(ReducerError::Terminal)
    );
    assert_eq!(allocator.profile_verifications(), 0);
    assert_eq!(claimant.profile_verifications(), 0);
    assert_eq!(allocator.delivered_payloads(), 0);
    assert_eq!(claimant.delivered_payloads(), 0);

    let (mut allocator, mut claimant) = confirmed_pair();
    let intent_frame = allocator.send_intent(&intent()).expect("intent");
    claimant.receive_frame(&intent_frame).expect("intent");
    let approval = claimant.decide(Decision::Approve).expect("approval");
    allocator
        .receive_frame(&extract_frame(&approval))
        .expect("approved");
    let digest = allocator.intent_digest().expect("intent digest");
    let frame = allocator
        .send_payload(&synthetic_payload(digest))
        .expect("profile-valid payload");
    let invitation_before = claimant.invitation_status();
    assert_eq!(claimant.terminal_reason(), None);
    assert_eq!(claimant.receive_frame(&frame).expect("authorized").len(), 1);
    assert_eq!(claimant.profile_verifications(), 1);
    assert_eq!(claimant.delivered_payloads(), 1);
    assert_eq!(claimant.terminal_reason(), None);
    assert_eq!(claimant.invitation_status(), invitation_before);
    assert!(claimant.session_ready());
}

#[test]
fn peer_signed_but_wrong_finished_is_terminal_and_erases_keys() {
    let m = materials();
    let record = bound_record(&m.invitation, &m.claimant_frame_bytes);
    let mut allocator = EndpointReducer::new(
        Side::Allocator,
        &m.invitation,
        record,
        m.allocator_key,
        m.allocator_monitor,
        m.allocator_pending,
        m.allocator_hash.clone(),
        m.claimant_hash.clone(),
        Box::new(SyntheticProfile::new(true)),
    )
    .expect("allocator");
    allocator
        .local_finished_frame()
        .expect("local finished")
        .expect("valid local Finished");

    let mut wrong_value = m.claimant_pending.local_finished();
    wrong_value[0] ^= 1;
    let control = build_bootstrap_control(
        &m.claimant_key,
        BootstrapPerformative::FinishedB,
        &ceremony_id(&m.invitation),
        &wrong_value,
        CausedBy::Multiple(vec![m.allocator_hash, m.claimant_hash]),
    )
    .expect("attacker controls its own ceremony key");
    let frame = ChannelFrame::Finished {
        side: Side::Claimant,
        control,
        value: wrong_value,
    };
    assert_eq!(allocator.receive_frame(&frame), Err(ReducerError::Channel));
    assert_eq!(
        allocator.terminal_reason(),
        Some(TerminalReason::KeyConfirmation)
    );
    assert!(allocator.secrets_erased());
    assert!(!allocator.session_ready());
    assert_eq!(allocator.delivered_payloads(), 0);
    assert_eq!(allocator.invitation_status(), InvitationStatus::Spent);
}

#[test]
fn test_022_two_valid_decision_siblings_received_in_sequence_are_terminal() {
    let m = materials();
    let allocator_id = m.allocator_key.key_id();
    let claimant_id = m.claimant_key.key_id();
    let record = bound_record(&m.invitation, &m.claimant_frame_bytes);
    let mut allocator = EndpointReducer::new(
        Side::Allocator,
        &m.invitation,
        record,
        m.allocator_key,
        m.allocator_monitor,
        m.allocator_pending,
        m.allocator_hash.clone(),
        m.claimant_hash.clone(),
        Box::new(SyntheticProfile::new(true)),
    )
    .expect("allocator");
    let allocator_finished = allocator
        .local_finished_frame()
        .expect("allocator finished")
        .expect("valid");
    let ChannelFrame::Finished {
        value: allocator_finished_value,
        ..
    } = allocator_finished
    else {
        unreachable!()
    };

    let claimant_finished_value = m.claimant_pending.local_finished();
    let claimant_finished_control = build_bootstrap_control(
        &m.claimant_key,
        BootstrapPerformative::FinishedB,
        &ceremony_id(&m.invitation),
        &claimant_finished_value,
        CausedBy::Multiple(vec![m.allocator_hash.clone(), m.claimant_hash.clone()]),
    )
    .expect("claimant Finished control");
    let claimant_finished = ChannelFrame::Finished {
        side: Side::Claimant,
        control: claimant_finished_control,
        value: claimant_finished_value,
    };
    let mut claimant_channel = m
        .claimant_pending
        .confirm(&allocator_finished_value)
        .expect("claimant confirms allocator");
    let opener_effects = allocator
        .receive_frame(&claimant_finished)
        .expect("allocator confirms claimant");
    let opener_frame = extract_frame(&opener_effects);
    let opener_plaintext = decode_sealed_plaintext(
        &claimant_channel
            .open(&opener_frame)
            .expect("open allocator role opener"),
    )
    .expect("opener plaintext");
    let ceremony = ceremony_id(&m.invitation);
    let (mut claimant_session, _) = SessionMonitor::open_for_ceremony(
        &ceremony,
        PairingRole::Claimant,
        &allocator_id,
        &claimant_id,
        &opener_plaintext.control,
    )
    .expect("claimant role monitor");

    let intent_frame = allocator.send_intent(&intent()).expect("allocator intent");
    let intent_plaintext = decode_sealed_plaintext(
        &claimant_channel
            .open(&intent_frame)
            .expect("open allocator intent"),
    )
    .expect("intent plaintext");
    let intent_body = intent_plaintext.body.as_deref().expect("intent body");
    let intent_value = decode_pairing_intent(intent_body).expect("intent value");
    let intent_bytes =
        cbcl_pairing::wire::encode_pairing_intent(&intent_value).expect("intent encoding");
    let intent_digest: [u8; 32] = Sha256::digest(intent_bytes).into();
    let intent_hash = claimant_session
        .admit(
            SessionPerformative::Intent,
            &intent_plaintext.control,
            intent_body,
        )
        .expect("intent CBCL")
        .content_hash()
        .to_owned();

    for (index, decision) in [Decision::Approve, Decision::Decline]
        .into_iter()
        .enumerate()
    {
        let body = encode_pairing_decision(&PairingDecision {
            intent_digest,
            decision,
        })
        .expect("decision body");
        let performative = match decision {
            Decision::Approve => SessionPerformative::Approve,
            Decision::Decline => SessionPerformative::Decline,
        };
        let control = build_session_control(
            &m.claimant_key,
            performative,
            &ceremony,
            &allocator_id,
            &body,
            CausedBy::Single(intent_hash.clone()),
        )
        .expect("decision control");
        assert_eq!(
            claimant_session
                .admit(performative, &control, &body)
                .expect("individual sibling verdict")
                .verdict(),
            ProtocolVerdict::Valid
        );
        let plaintext = encode_sealed_plaintext(&SealedPlaintext {
            control,
            body: Some(body),
        })
        .expect("decision plaintext");
        let frame = claimant_channel.seal(&plaintext).expect("contiguous frame");
        if index == 0 {
            assert!(allocator
                .receive_frame(&frame)
                .expect("approval accepted")
                .is_empty());
        } else {
            assert_eq!(
                allocator.receive_frame(&frame),
                Err(ReducerError::DecisionConflict)
            );
        }
    }
    assert_eq!(
        allocator.terminal_reason(),
        Some(TerminalReason::DecisionConflict)
    );
    assert!(allocator.secrets_erased());
    assert_eq!(allocator.delivered_payloads(), 0);
}
