//! Deterministic property and invariant gate for SPEC-072.

use cbcl_pairing::{
    channel::{ChannelError, PendingChannel},
    cpace::{finish, start},
    mailbox::{
        reap, transition, AllocationInput, Mailbox, MailboxCommand, MailboxSnapshot, MailboxStatus,
        Membership, MembershipHash, MAX_FRAMES_PER_MEMBERSHIP, MAX_FRAME_BODY_BYTES,
    },
    wire::{
        decode_application_payload, decode_channel_frame, decode_client_message, decode_invitation,
        decode_pairing_decision, decode_pairing_intent, decode_sealed_plaintext,
        decode_server_message, encode_application_payload, encode_channel_frame,
        encode_client_message, encode_invitation, encode_pairing_decision, encode_pairing_intent,
        encode_sealed_plaintext, encode_server_message, ChannelFrame, Direction, Side,
    },
};

const NOW: u64 = 1_800_000_000;

#[derive(Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn hostile_bytes_roundtrip_if_and_only_if_recognised() {
    let mut rng = Rng(0x0720_0050_cafe_f00d);
    for _ in 0..4_096 {
        let length = (rng.next() as usize) % 768;
        let input = rng.bytes(length);

        if let Ok(value) = decode_invitation(&input) {
            assert_eq!(encode_invitation(&value).expect("invitation"), input);
        }
        if let Ok(value) = decode_client_message(&input) {
            assert_eq!(encode_client_message(&value).expect("client"), input);
        }
        if let Ok(value) = decode_server_message(&input) {
            assert_eq!(encode_server_message(&value).expect("server"), input);
        }
        if let Ok(value) = decode_channel_frame(&input) {
            assert_eq!(encode_channel_frame(&value).expect("channel"), input);
        }
        if let Ok(value) = decode_sealed_plaintext(&input) {
            assert_eq!(encode_sealed_plaintext(&value).expect("plaintext"), input);
        }
        if let Ok(value) = decode_pairing_intent(&input) {
            assert_eq!(encode_pairing_intent(&value).expect("intent"), input);
        }
        if let Ok(value) = decode_pairing_decision(&input) {
            assert_eq!(encode_pairing_decision(&value).expect("decision"), input);
        }
        if let Ok(value) = decode_application_payload(&input) {
            assert_eq!(encode_application_payload(&value).expect("payload"), input);
        }
    }
}

#[test]
fn random_mailbox_traces_preserve_blind_bounded_state() {
    for seed in 1..=256_u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let expires_at = NOW + 600;
        let mut state = Some(
            Mailbox::allocate(AllocationInput {
                mailbox_id: [seed as u8; 32],
                nameplate: Some((seed % 1_000_000_000) as u32),
                allocator_hash: membership_hash(seed as u8),
                now: NOW,
                ttl_seconds: Some(600),
            })
            .expect("allocation"),
        );

        for step in 0..96_u64 {
            let Some(current) = state.as_ref() else {
                break;
            };
            assert_snapshot(&current.snapshot(), expires_at);
            if matches!(current.status(), MailboxStatus::Terminal(_)) {
                break;
            }
            let side = if rng.next() & 1 == 0 {
                Membership::Allocator
            } else {
                Membership::Claimant
            };
            let command = match rng.next() % 5 {
                0 => MailboxCommand::Claim {
                    claimant_hash: membership_hash((rng.next() >> 8) as u8),
                },
                1 | 2 => MailboxCommand::Put {
                    sender: side,
                    seq: (rng.next() % 20) as u8,
                    body: {
                        let length = 1 + (rng.next() as usize % 96);
                        rng.bytes(length)
                    },
                },
                3 => MailboxCommand::Ack {
                    sender: side,
                    peer_seq: (rng.next() % 20) as u8,
                },
                _ => MailboxCommand::Open {
                    membership_hash: membership_hash((rng.next() >> 16) as u8),
                },
            };
            if let Ok(outcome) = transition(current, NOW + step, command) {
                state = outcome.state;
            }
        }

        if let Some(current) = state {
            assert_snapshot(&current.snapshot(), expires_at);
            assert!(reap(&current, expires_at).expect("reap").state.is_none());
        }
    }
}

#[test]
fn random_channel_payloads_are_contiguous_and_corruption_is_terminal() {
    let mut rng = Rng(0x0720_0040_feed_face);
    for _ in 0..48 {
        let (mut allocator, mut claimant) = confirmed_pair();
        for expected_counter in 0..8_u64 {
            let length = 1 + (rng.next() as usize % 2_048);
            let payload = rng.bytes(length);
            let frame = allocator.seal(&payload).expect("seal");
            assert!(matches!(
                &frame,
                ChannelFrame::Sealed {
                    direction: Direction::AllocatorToClaimant,
                    counter,
                    ..
                } if *counter == expected_counter
            ));
            assert_eq!(claimant.open(&frame).expect("open"), payload);
        }

        let (mut allocator, mut claimant) = confirmed_pair();
        let mut frame = allocator.seal(&rng.bytes(32)).expect("seal corrupt");
        let ChannelFrame::Sealed { ciphertext, .. } = &mut frame else {
            unreachable!()
        };
        let index = (rng.next() as usize) % ciphertext.len();
        ciphertext[index] ^= 1;
        assert_eq!(claimant.open(&frame), Err(ChannelError::InvalidTag));
        assert_eq!(claimant.open(&frame), Err(ChannelError::Terminal));
    }
}

#[test]
fn intent_state_retains_no_display_metadata() {
    let source = include_str!("../src/endpoint.rs");
    let start = source.find("struct IntentRecord").expect("IntentRecord");
    let end = source[start..]
        .find("struct DecisionRecord")
        .map(|offset| start + offset)
        .expect("DecisionRecord");
    let record = &source[start..end];
    for prohibited in [
        "authority_summary",
        "allocator_claim",
        "claimant_claim",
        "PairingIntent",
        "DisplayIntent",
    ] {
        assert!(
            !record.contains(prohibited),
            "IntentRecord retained {prohibited}"
        );
    }
}

fn membership_hash(fill: u8) -> MembershipHash {
    MembershipHash::new([fill; 32])
}

fn assert_snapshot(snapshot: &MailboxSnapshot, expires_at: u64) {
    assert_eq!(snapshot.expires_at, expires_at);
    assert!(snapshot.membership_hashes.len() <= 2);
    for membership in [Membership::Allocator, Membership::Claimant] {
        let records: Vec<_> = snapshot
            .sequences
            .iter()
            .filter(|record| record.owner == membership)
            .collect();
        assert!(records.len() <= MAX_FRAMES_PER_MEMBERSHIP);
        for (expected, record) in records.iter().enumerate() {
            assert_eq!(usize::from(record.seq), expected);
            assert!(record.body_len <= MAX_FRAME_BODY_BYTES);
            assert!(record
                .body
                .as_ref()
                .is_none_or(|body| body.len() == record.body_len));
        }
    }
    if matches!(snapshot.status, MailboxStatus::Terminal(_)) {
        assert!(snapshot
            .sequences
            .iter()
            .all(|record| record.body.is_none()));
    }
}

fn confirmed_pair() -> (
    cbcl_pairing::channel::SecureChannel,
    cbcl_pairing::channel::SecureChannel,
) {
    let sid = [0x55; 32];
    let (allocator_state, allocator_message) = start(
        Side::Allocator,
        b"property secret",
        b"property context",
        &sid,
        b"allocator AD",
        [0x41; 32],
    )
    .expect("allocator CPace");
    let (claimant_state, claimant_message) = start(
        Side::Claimant,
        b"property secret",
        b"property context",
        &sid,
        b"claimant AD",
        [0x42; 32],
    )
    .expect("claimant CPace");
    let allocator_isk = finish(allocator_state, &claimant_message).expect("allocator finish");
    let claimant_isk = finish(claimant_state, &allocator_message).expect("claimant finish");
    let allocator = PendingChannel::new(
        Side::Allocator,
        allocator_isk,
        b"public context",
        b"allocator frame",
        b"claimant frame",
    )
    .expect("allocator pending");
    let claimant = PendingChannel::new(
        Side::Claimant,
        claimant_isk,
        b"public context",
        b"allocator frame",
        b"claimant frame",
    )
    .expect("claimant pending");
    let allocator_finished = allocator.local_finished();
    let claimant_finished = claimant.local_finished();
    (
        allocator
            .confirm(&claimant_finished)
            .expect("allocator channel"),
        claimant
            .confirm(&allocator_finished)
            .expect("claimant channel"),
    )
}
