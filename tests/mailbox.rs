//! SPEC-072 mailbox-core detailed Red and Green Gate.

use cbcl_pairing::{
    mailbox::{
        reap, transition, AllocationInput, Mailbox, MailboxCommand, MailboxEffect, MailboxError,
        MailboxStatus, Membership, MembershipHash, DEFAULT_TTL_SECONDS, MAX_FRAME_BODY_BYTES,
    },
    wire::CloseReason,
};

const NOW: u64 = 1_800_000_000;

fn hash(fill: u8) -> MembershipHash {
    MembershipHash::new([fill; 32])
}

fn input(ttl_seconds: Option<u16>) -> AllocationInput {
    AllocationInput {
        mailbox_id: [0x11; 32],
        nameplate: Some(123_456_789),
        allocator_hash: hash(0xa1),
        now: NOW,
        ttl_seconds,
    }
}

fn allocated() -> Mailbox {
    Mailbox::allocate(input(None)).expect("mailbox allocates")
}

fn apply(state: &mut Option<Mailbox>, now: u64, command: MailboxCommand) -> Vec<MailboxEffect> {
    let outcome = transition(state.as_ref().expect("mailbox exists"), now, command)
        .expect("transition succeeds");
    *state = outcome.state;
    outcome.effects
}

fn claim(state: &mut Option<Mailbox>) {
    apply(
        state,
        NOW,
        MailboxCommand::Claim {
            claimant_hash: hash(0xb2),
        },
    );
}

fn body_records(state: &Option<Mailbox>) -> usize {
    state
        .as_ref()
        .expect("mailbox exists")
        .snapshot()
        .sequences
        .iter()
        .filter(|record| record.body.is_some())
        .count()
}

#[test]
fn test_001_offline_peer_receives_exact_queued_frame_and_ack_deletes_it() {
    let mut state = Some(allocated());
    claim(&mut state);
    let body = b"opaque frame zero".to_vec();

    let put_effects = apply(
        &mut state,
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: body.clone(),
        },
    );
    assert!(put_effects.contains(&MailboxEffect::Deliver {
        recipient: Membership::Claimant,
        peer_seq: 0,
        body: body.clone(),
    }));
    assert_eq!(body_records(&state), 1);

    let open_effects = apply(
        &mut state,
        NOW + 2,
        MailboxCommand::Open {
            membership_hash: hash(0xb2),
        },
    );
    assert!(open_effects.contains(&MailboxEffect::Deliver {
        recipient: Membership::Claimant,
        peer_seq: 0,
        body,
    }));

    let ack_effects = apply(
        &mut state,
        NOW + 3,
        MailboxCommand::Ack {
            sender: Membership::Claimant,
            peer_seq: 0,
        },
    );
    assert!(ack_effects.contains(&MailboxEffect::BodyDeleted {
        owner: Membership::Allocator,
        seq: 0,
    }));
    assert_eq!(body_records(&state), 0);
}

#[test]
fn test_002_snapshot_contains_only_blind_mailbox_domain_state() {
    let mut state = Some(allocated());
    claim(&mut state);
    apply(
        &mut state,
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: vec![0xde, 0xad, 0xbe, 0xef],
        },
    );

    let snapshot = state.as_ref().expect("state").snapshot();
    assert_eq!(snapshot.mailbox_id, [0x11; 32]);
    assert_eq!(snapshot.nameplate, Some(123_456_789));
    assert_eq!(snapshot.membership_hashes, vec![hash(0xa1), hash(0xb2)]);
    assert_eq!(snapshot.sequences.len(), 1);
    assert_eq!(snapshot.sequences[0].body_len, 4);
    assert_eq!(
        snapshot.sequences[0].body,
        Some(vec![0xde, 0xad, 0xbe, 0xef])
    );

    let domain_state = format!("{snapshot:?}").to_ascii_lowercase();
    for prohibited in ["pairing key", "mac verdict", "identity", "intent", "grant"] {
        assert!(!domain_state.contains(prohibited), "stored {prohibited}");
    }
}

#[test]
fn test_003_third_distinct_claim_crowds_and_allocates_no_membership() {
    let mut state = Some(allocated());
    claim(&mut state);
    apply(
        &mut state,
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: vec![1, 2, 3],
        },
    );

    let effects = apply(
        &mut state,
        NOW + 2,
        MailboxCommand::Claim {
            claimant_hash: hash(0xc3),
        },
    );
    let snapshot = state.as_ref().expect("tombstone remains").snapshot();
    assert_eq!(
        snapshot.status,
        MailboxStatus::Terminal(CloseReason::Crowded)
    );
    assert_eq!(snapshot.membership_hashes, vec![hash(0xa1), hash(0xb2)]);
    assert!(!snapshot.membership_hashes.contains(&hash(0xc3)));
    assert_eq!(body_records(&state), 0);
    assert!(effects.contains(&MailboxEffect::Terminal(CloseReason::Crowded)));
}

#[test]
fn test_029_existing_claimant_hash_cannot_reclaim() {
    let mut state = Some(allocated());
    claim(&mut state);
    let before = state.as_ref().expect("state").snapshot();

    assert_eq!(
        transition(
            state.as_ref().expect("state"),
            NOW + 1,
            MailboxCommand::Claim {
                claimant_hash: hash(0xb2),
            },
        ),
        Err(MailboxError::MembershipCollision)
    );
    assert_eq!(state.as_ref().expect("state").snapshot(), before);
}

#[test]
fn test_004_sequence_retries_are_idempotent_and_conflicts_are_terminal() {
    let mut state = Some(allocated());
    claim(&mut state);
    let original = vec![1, 2, 3];
    apply(
        &mut state,
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: original.clone(),
        },
    );
    let before_retry = state.as_ref().expect("state").snapshot();

    let retry_effects = apply(
        &mut state,
        NOW + 2,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: original,
        },
    );
    assert_eq!(state.as_ref().expect("state").snapshot(), before_retry);
    assert_eq!(
        retry_effects,
        vec![MailboxEffect::Stored {
            sender: Membership::Allocator,
            seq: 0,
            replay: true,
        }]
    );

    let conflict_effects = apply(
        &mut state,
        NOW + 3,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: vec![9, 9, 9],
        },
    );
    assert_eq!(
        state.as_ref().expect("state").status(),
        MailboxStatus::Terminal(CloseReason::Conflict)
    );
    assert_eq!(body_records(&state), 0);
    assert!(conflict_effects.contains(&MailboxEffect::Terminal(CloseReason::Conflict)));

    let gap_state = Some(allocated());
    let before_gap = gap_state.as_ref().expect("state").snapshot();
    let error = transition(
        gap_state.as_ref().expect("state"),
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 2,
            body: vec![1],
        },
    )
    .expect_err("gap fails");
    assert_eq!(
        error,
        MailboxError::SequenceGap {
            expected: 0,
            got: 2
        }
    );
    assert_eq!(gap_state.as_ref().expect("state").snapshot(), before_gap);
}

#[test]
fn test_013_lifetime_bounds_terminal_deletion_and_original_expiry_reaping() {
    assert_eq!(
        allocated().expires_at(),
        NOW + u64::from(DEFAULT_TTL_SECONDS)
    );
    assert_eq!(
        Mailbox::allocate(input(Some(60)))
            .expect("minimum TTL")
            .expires_at(),
        NOW + 60
    );
    assert_eq!(
        Mailbox::allocate(input(Some(600)))
            .expect("maximum TTL")
            .expires_at(),
        NOW + 600
    );
    assert_eq!(
        Mailbox::allocate(input(Some(59))),
        Err(MailboxError::LifetimeOutOfRange)
    );
    assert_eq!(
        Mailbox::allocate(input(Some(601))),
        Err(MailboxError::LifetimeOutOfRange)
    );

    let mut bounded = Some(allocated());
    for seq in 0..16 {
        apply(
            &mut bounded,
            NOW + 1,
            MailboxCommand::Put {
                sender: Membership::Allocator,
                seq,
                body: vec![0; if seq == 0 { MAX_FRAME_BODY_BYTES } else { 1 }],
            },
        );
    }
    assert_eq!(
        transition(
            bounded.as_ref().expect("state"),
            NOW + 2,
            MailboxCommand::Put {
                sender: Membership::Allocator,
                seq: 16,
                body: vec![1],
            },
        ),
        Err(MailboxError::FrameLimit)
    );

    let oversize = transition(
        &allocated(),
        NOW + 1,
        MailboxCommand::Put {
            sender: Membership::Allocator,
            seq: 0,
            body: vec![0; MAX_FRAME_BODY_BYTES + 1],
        },
    );
    assert_eq!(oversize, Err(MailboxError::BodySize));

    let expires_at = bounded.as_ref().expect("state").expires_at();
    apply(
        &mut bounded,
        NOW + 100,
        MailboxCommand::Close {
            sender: Membership::Allocator,
        },
    );
    assert_eq!(body_records(&bounded), 0);
    assert_eq!(
        bounded.as_ref().expect("tombstone").expires_at(),
        expires_at
    );
    assert!(reap(bounded.as_ref().expect("state"), expires_at - 1)
        .expect("not expired")
        .state
        .is_some());
    assert!(reap(bounded.as_ref().expect("state"), expires_at)
        .expect("expires")
        .state
        .is_none());
}
