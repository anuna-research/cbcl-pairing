#![no_main]

use cbcl_pairing::{
    channel::PendingChannel,
    cpace::{finish, start},
    wire::{ChannelFrame, Direction, Side},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let sid = [0x55; 32];
    let (allocator_state, allocator_message) = start(
        Side::Allocator,
        b"fuzz secret",
        b"fuzz context",
        &sid,
        b"allocator AD",
        [0x41; 32],
    )
    .expect("allocator CPace");
    let (claimant_state, claimant_message) = start(
        Side::Claimant,
        b"fuzz secret",
        b"fuzz context",
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
    let mut receiver = claimant
        .confirm(&allocator_finished)
        .expect("claimant channel");
    drop(allocator.confirm(&claimant_finished).expect("allocator channel"));

    let mut counter_bytes = [0_u8; 8];
    for (destination, source) in counter_bytes.iter_mut().zip(input.iter().copied()) {
        *destination = source;
    }
    let frame = ChannelFrame::Sealed {
        direction: if input.get(8).copied().unwrap_or(0) & 1 == 0 {
            Direction::AllocatorToClaimant
        } else {
            Direction::ClaimantToAllocator
        },
        counter: u64::from_be_bytes(counter_bytes),
        ciphertext: input.get(9..).unwrap_or_default().iter().copied().take(4096).collect(),
    };
    let _ = receiver.open(&frame);
});
