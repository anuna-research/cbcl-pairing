//! SPEC-001 TEST-065 allocator bootstrap recovery Red Gate.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        CredentialV2AllocatorBootstrap, CredentialV2AllocatorBootstrapPhase, CredentialV2Carrier,
        CredentialV2CarrierInput, CredentialV2CheckpointNonce, CredentialV2Context,
        CredentialV2Frame, CredentialV2Presence, CredentialV2RelayState,
    },
    wire::{claim_commitment, ClaimToken, Side},
};

const NOW: u64 = 1_800_000_100;
const EXPIRY: u64 = 1_800_000_900;
const MAILBOX: [u8; 32] = [0x21; 32];
const CEREMONY: [u8; 32] = [0x22; 32];
const CLAIM: [u8; 16] = [0x23; 16];
const CPACE_SECRET: [u8; 16] = [0x24; 16];
const PROFILE_DIGEST: [u8; 32] = [0x25; 32];
const MEMBERSHIP: [u8; 32] = [0x26; 32];
const WRAPPING_KEY: [u8; 32] = [0x27; 32];

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: MAILBOX,
        carrier_ceremony_id: CEREMONY,
        carrier_nonce: [0x28; 32],
        claim_commitment: claim_commitment(MAILBOX, &ClaimToken::new(CLAIM)),
        relay_expires_at: EXPIRY,
        expected_allocator_key: Some([0x29; 32]),
    })
    .unwrap()
}

fn allocator() -> CredentialV2AllocatorBootstrap {
    CredentialV2AllocatorBootstrap::new(
        carrier(),
        CredentialV2Presence::new(CPACE_SECRET, CLAIM),
        PROFILE_DIGEST,
        CredentialV2RelayState::new(MEMBERSHIP),
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
    )
    .unwrap()
}

fn restore(checkpoint: &[u8], generation: u64) -> CredentialV2AllocatorBootstrap {
    CredentialV2AllocatorBootstrap::restore_checkpoint(
        checkpoint,
        &WRAPPING_KEY,
        &carrier(),
        generation,
        NOW,
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
    )
    .unwrap()
}

#[test]
fn test_065_allocator_restores_every_pre_finished_state_and_erases_presence_secrets() {
    let mut allocator = allocator();
    let allocated = allocator
        .seal_checkpoint(
            &WRAPPING_KEY,
            1,
            CredentialV2CheckpointNonce::from_csprng([0x31; 12]),
            NOW,
        )
        .unwrap();
    let mut allocator = restore(allocated.as_bytes(), 1);
    assert_eq!(
        allocator.phase(),
        CredentialV2AllocatorBootstrapPhase::Allocated
    );
    assert_eq!(allocator.relay_state().membership_token(), &MEMBERSHIP);

    allocator.claimant_admitted().unwrap();
    assert!(
        allocator.claimant_admitted().is_err(),
        "T is one-use and erased"
    );
    let admitted = allocator
        .seal_checkpoint(
            &WRAPPING_KEY,
            2,
            CredentialV2CheckpointNonce::from_csprng([0x32; 12]),
            NOW,
        )
        .unwrap();
    let mut allocator = restore(admitted.as_bytes(), 2);
    assert_eq!(
        allocator.phase(),
        CredentialV2AllocatorBootstrapPhase::Claimed
    );

    let allocator_share = allocator.start_cpace([0x33; 32]).unwrap();
    assert_eq!(allocator.cached_outbound_frame(), Some(&allocator_share));
    let shared = allocator
        .seal_checkpoint(
            &WRAPPING_KEY,
            3,
            CredentialV2CheckpointNonce::from_csprng([0x34; 12]),
            NOW,
        )
        .unwrap();
    let mut allocator = restore(shared.as_bytes(), 3);
    assert_eq!(
        allocator.phase(),
        CredentialV2AllocatorBootstrapPhase::ShareSent
    );
    assert_eq!(allocator.cached_outbound_frame(), Some(&allocator_share));

    let context = CredentialV2Context::derive(&carrier(), PROFILE_DIGEST).unwrap();
    let claimant_presence = CredentialV2Presence::new(CPACE_SECRET, CLAIM);
    let (claimant_state, claimant_message) = context
        .start_cpace(Side::Claimant, &claimant_presence, [0x35; 32])
        .unwrap();
    let claimant_share = CredentialV2Frame::cpace(&claimant_message).unwrap();
    let allocator_finished = allocator.receive_cpace(&claimant_share).unwrap();
    assert_eq!(allocator.cached_outbound_frame(), Some(&allocator_finished));
    let pending = allocator
        .seal_checkpoint(
            &WRAPPING_KEY,
            4,
            CredentialV2CheckpointNonce::from_csprng([0x36; 12]),
            NOW,
        )
        .unwrap();
    let allocator = restore(pending.as_bytes(), 4);
    assert_eq!(
        allocator.phase(),
        CredentialV2AllocatorBootstrapPhase::FinishedSent
    );
    assert_eq!(allocator.cached_outbound_frame(), Some(&allocator_finished));

    let claimant_isk = cpace::finish(
        claimant_state,
        allocator_share
            .cpace_message()
            .expect("allocator CPace frame"),
    )
    .unwrap();
    let claimant_pending = cbcl_pairing::credential_v2::PendingCredentialV2Channel::new(
        Side::Claimant,
        claimant_isk,
        context.public_context(),
        &cbcl_pairing::credential_v2::encode_frame(&allocator_share).unwrap(),
        &cbcl_pairing::credential_v2::encode_frame(&claimant_share).unwrap(),
    )
    .unwrap();
    let claimant_finished = claimant_pending.local_finished_frame();
    let (mut allocator_channel, relay_state) = allocator.confirm(&claimant_finished).unwrap();
    let mut claimant_channel = claimant_pending.confirm(&allocator_finished).unwrap();
    assert_eq!(relay_state.membership_token(), &MEMBERSHIP);

    let sealed = allocator_channel
        .seal(b"post-Finished proves restored schedule")
        .unwrap();
    assert_eq!(
        claimant_channel.open(&sealed).unwrap(),
        b"post-Finished proves restored schedule"
    );
}

#[test]
fn test_065_allocator_bootstrap_checkpoint_requires_numeric_live_expiry_and_exact_bindings() {
    let mut allocator = allocator();
    let checkpoint = allocator
        .seal_checkpoint(
            &WRAPPING_KEY,
            1,
            CredentialV2CheckpointNonce::from_csprng([0x41; 12]),
            NOW,
        )
        .unwrap();

    assert!(CredentialV2AllocatorBootstrap::restore_checkpoint(
        checkpoint.as_bytes(),
        &[0xff; 32],
        &carrier(),
        1,
        NOW,
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
    )
    .is_err());
    assert!(CredentialV2AllocatorBootstrap::restore_checkpoint(
        checkpoint.as_bytes(),
        &WRAPPING_KEY,
        &carrier(),
        2,
        NOW,
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
    )
    .is_err());
    assert!(CredentialV2AllocatorBootstrap::restore_checkpoint(
        checkpoint.as_bytes(),
        &WRAPPING_KEY,
        &carrier(),
        1,
        EXPIRY,
        cbcl_pairing::credential_v2::CredentialV2AllocatorMode::Full,
    )
    .is_err());
}
