#![no_main]

use cbcl_pairing::mailbox::{
    transition, AllocationInput, Mailbox, MailboxCommand, MailboxStatus, Membership,
    MembershipHash, MAX_FRAME_BODY_BYTES, MAX_FRAMES_PER_MEMBERSHIP,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut state = Mailbox::allocate(AllocationInput {
        mailbox_id: [0x11; 32],
        nameplate: Some(72),
        allocator_hash: MembershipHash::new([0xa1; 32]),
        now: 1_800_000_000,
        ttl_seconds: Some(600),
    })
    .expect("fixed allocation");

    for (step, chunk) in input.chunks(8).take(96).enumerate() {
        if matches!(state.status(), MailboxStatus::Terminal(_)) {
            break;
        }
        let byte = |index: usize| chunk.get(index).copied().unwrap_or(0);
        let side = if byte(1) & 1 == 0 {
            Membership::Allocator
        } else {
            Membership::Claimant
        };
        let command = match byte(0) % 5 {
            0 => MailboxCommand::Claim {
                claimant_hash: MembershipHash::new([byte(2); 32]),
            },
            1 | 2 => MailboxCommand::Put {
                sender: side,
                seq: byte(2) % 20,
                body: vec![byte(4); usize::from(byte(3) % 96) + 1],
            },
            3 => MailboxCommand::Ack {
                sender: side,
                peer_seq: byte(2) % 20,
            },
            _ => MailboxCommand::Open {
                membership_hash: MembershipHash::new([byte(2); 32]),
            },
        };
        if let Ok(outcome) = transition(&state, 1_800_000_000 + step as u64, command) {
            let Some(next) = outcome.state else {
                break;
            };
            state = next;
        }
        let snapshot = state.snapshot();
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
            }
        }
        if matches!(snapshot.status, MailboxStatus::Terminal(_)) {
            assert!(snapshot.sequences.iter().all(|record| record.body.is_none()));
        }
    }
});
