//! Secure-channel Red Gate and CON-004 behavioural coverage.

use cbcl_pairing::{
    channel::{derive_nonce, sealed_aad, ChannelError, PendingChannel, MAX_SEALED_PLAINTEXT},
    cpace::{finish, start, IntermediateSessionKey},
    wire::{ChannelFrame, Direction, Side},
};

const PUBLIC_CONTEXT: &[u8] = b"public-context";
const A_FRAME: &[u8] = b"allocator-cpace-frame";
const B_FRAME: &[u8] = b"claimant-cpace-frame";

fn bytes(hexadecimal: &str) -> Vec<u8> {
    hex::decode(hexadecimal).expect("valid expected hex")
}

fn official_isks() -> (IntermediateSessionKey, IntermediateSessionKey) {
    let prs = b"Password";
    let ci = b"\x0bA_initiator\x0bB_responder";
    let sid = bytes("7e4b4791d6a8ef019b936c79fb7f2c57");
    let ya: [u8; 32] = bytes("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
        .try_into()
        .expect("ya");
    let yb: [u8; 32] = bytes("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a")
        .try_into()
        .expect("yb");
    let (a_state, a_message) = start(Side::Allocator, prs, ci, &sid, b"ADa", ya).expect("start A");
    let (b_state, b_message) = start(Side::Claimant, prs, ci, &sid, b"ADb", yb).expect("start B");
    (
        finish(a_state, &b_message).expect("finish A"),
        finish(b_state, &a_message).expect("finish B"),
    )
}

fn pending_pair() -> (PendingChannel, PendingChannel) {
    let (a_isk, b_isk) = official_isks();
    let allocator = PendingChannel::new(Side::Allocator, a_isk, PUBLIC_CONTEXT, A_FRAME, B_FRAME)
        .expect("derive allocator channel");
    let claimant = PendingChannel::new(Side::Claimant, b_isk, PUBLIC_CONTEXT, A_FRAME, B_FRAME)
        .expect("derive claimant channel");
    (allocator, claimant)
}

#[test]
fn transcript_hkdf_finished_and_exporter_match_independent_values() {
    let (allocator, claimant) = pending_pair();
    let transcript_hash: [u8; 64] = bytes(
        "bf599dc026a51800c941265721b9dc8b51e36564cc4b9c93aa2bd2e45c581496\
         0f421efb58d83ae9e2427eb2beb32720a640e6380f429b2c703341e611fa0de8",
    )
    .try_into()
    .expect("TH");
    assert_eq!(allocator.transcript_hash(), transcript_hash);
    assert_eq!(claimant.transcript_hash(), transcript_hash);
    assert_eq!(
        allocator.local_finished().as_slice(),
        bytes(
            "3e120d0b3f939dc26017553c5213e8048306156bb95cbeaaab4f520c19bdcc9d\
             34b4c819489160c9014b11204646dc3fc7880147678eb87be483c5c35cb68c52",
        )
    );
    assert_eq!(
        claimant.local_finished().as_slice(),
        bytes(
            "03027b5bdbe340ea294ee4fb424404e9e61da8c9c68fb7edeeaa54496f14b5ee\
             2cd9cfa3613f6a9b1a6a5da8df08c5c8e69c2cfffccc12de443a8283d2da73a3",
        )
    );

    let a_finished = allocator.local_finished();
    let b_finished = claimant.local_finished();
    let allocator = allocator.confirm(&b_finished).expect("confirm A");
    let claimant = claimant.confirm(&a_finished).expect("confirm B");
    let exporter = bytes("3baec85d3347e8c0b0f2c19df9e204c6a1f1b9259212388dc56986f602e1cdc2");
    assert_eq!(allocator.exporter().as_slice(), exporter);
    assert_eq!(allocator.exporter(), claimant.exporter());
}

#[test]
fn each_corrupt_finished_value_blocks_channel_activation() {
    let (allocator, claimant) = pending_pair();
    let mut claimant_finished = claimant.local_finished();
    claimant_finished[0] ^= 1;
    assert!(matches!(
        allocator.confirm(&claimant_finished),
        Err(ChannelError::FinishedMismatch)
    ));

    let (allocator, claimant) = pending_pair();
    let mut allocator_finished = allocator.local_finished();
    allocator_finished[63] ^= 1;
    assert!(matches!(
        claimant.confirm(&allocator_finished),
        Err(ChannelError::FinishedMismatch)
    ));
}

#[test]
fn wrong_cpace_secret_fails_explicit_key_confirmation() {
    let sid = [9_u8; 32];
    let (a_state, a_message) = start(
        Side::Allocator,
        b"correct secret",
        b"shared context",
        &sid,
        b"ADa",
        [3; 32],
    )
    .expect("start A");
    let (b_state, b_message) = start(
        Side::Claimant,
        b"wrong secret",
        b"shared context",
        &sid,
        b"ADb",
        [4; 32],
    )
    .expect("start B");
    let a_isk = finish(a_state, &b_message).expect("finish A");
    let b_isk = finish(b_state, &a_message).expect("finish B");
    let allocator = PendingChannel::new(Side::Allocator, a_isk, PUBLIC_CONTEXT, A_FRAME, B_FRAME)
        .expect("derive A");
    let claimant = PendingChannel::new(Side::Claimant, b_isk, PUBLIC_CONTEXT, A_FRAME, B_FRAME)
        .expect("derive B");
    let a_finished = allocator.local_finished();
    let b_finished = claimant.local_finished();
    assert!(matches!(
        allocator.confirm(&b_finished),
        Err(ChannelError::FinishedMismatch)
    ));
    assert!(matches!(
        claimant.confirm(&a_finished),
        Err(ChannelError::FinishedMismatch)
    ));
}

#[test]
fn both_directions_roundtrip_with_independent_contiguous_counters() {
    let (allocator, claimant) = pending_pair();
    let a_finished = allocator.local_finished();
    let b_finished = claimant.local_finished();
    let mut allocator = allocator.confirm(&b_finished).expect("confirm A");
    let mut claimant = claimant.confirm(&a_finished).expect("confirm B");

    let a0 = allocator.seal(b"allocator zero").expect("seal A0");
    let b0 = claimant.seal(b"claimant zero").expect("seal B0");
    assert!(matches!(
        &a0,
        ChannelFrame::Sealed {
            direction: Direction::AllocatorToClaimant,
            counter: 0,
            ..
        }
    ));
    assert!(matches!(
        &b0,
        ChannelFrame::Sealed {
            direction: Direction::ClaimantToAllocator,
            counter: 0,
            ..
        }
    ));
    assert_eq!(claimant.open(&a0).expect("open A0"), b"allocator zero");
    assert_eq!(allocator.open(&b0).expect("open B0"), b"claimant zero");

    let a1 = allocator.seal(b"allocator one").expect("seal A1");
    let b1 = claimant.seal(b"claimant one").expect("seal B1");
    assert!(matches!(&a1, ChannelFrame::Sealed { counter: 1, .. }));
    assert!(matches!(&b1, ChannelFrame::Sealed { counter: 1, .. }));
    assert_eq!(claimant.open(&a1).expect("open A1"), b"allocator one");
    assert_eq!(allocator.open(&b1).expect("open B1"), b"claimant one");
}

#[test]
fn transcript_and_directional_keys_are_separated() {
    let (mut allocator, mut claimant) = confirmed_pair();
    let a_frame = allocator.seal(b"same plaintext").expect("seal A");
    let b_frame = claimant.seal(b"same plaintext").expect("seal B");
    let (
        ChannelFrame::Sealed {
            ciphertext: a_ciphertext,
            ..
        },
        ChannelFrame::Sealed {
            ciphertext: b_ciphertext,
            ..
        },
    ) = (&a_frame, &b_frame)
    else {
        panic!("sealed frames")
    };
    assert_ne!(a_ciphertext, b_ciphertext);

    let (a_isk, b_isk) = official_isks();
    let allocator = PendingChannel::new(Side::Allocator, a_isk, PUBLIC_CONTEXT, A_FRAME, B_FRAME)
        .expect("derive A");
    let claimant = PendingChannel::new(Side::Claimant, b_isk, b"changed-context", A_FRAME, B_FRAME)
        .expect("derive B");
    assert_ne!(allocator.transcript_hash(), claimant.transcript_hash());
    let a_finished = allocator.local_finished();
    let b_finished = claimant.local_finished();
    assert!(matches!(
        allocator.confirm(&b_finished),
        Err(ChannelError::FinishedMismatch)
    ));
    assert!(matches!(
        claimant.confirm(&a_finished),
        Err(ChannelError::FinishedMismatch)
    ));
}

#[test]
fn replay_gap_wrong_direction_and_bad_tag_are_terminal() {
    let (allocator, claimant) = confirmed_pair();
    let mut cases = Vec::new();

    let (mut sender, mut receiver) = (allocator, claimant);
    let frame = sender.seal(b"once").expect("seal");
    assert_eq!(receiver.open(&frame).expect("first open"), b"once");
    assert_eq!(receiver.open(&frame), Err(ChannelError::CounterMismatch));
    assert_eq!(receiver.open(&frame), Err(ChannelError::Terminal));
    cases.push(());

    let (mut sender, mut receiver) = confirmed_pair();
    let _zero = sender.seal(b"zero").expect("seal zero");
    let one = sender.seal(b"one").expect("seal one");
    assert_eq!(receiver.open(&one), Err(ChannelError::CounterMismatch));
    assert_eq!(receiver.open(&one), Err(ChannelError::Terminal));
    cases.push(());

    let (mut sender, mut receiver) = confirmed_pair();
    let mut wrong_direction = sender.seal(b"direction").expect("seal");
    if let ChannelFrame::Sealed { direction, .. } = &mut wrong_direction {
        *direction = Direction::ClaimantToAllocator;
    }
    assert_eq!(
        receiver.open(&wrong_direction),
        Err(ChannelError::DirectionMismatch)
    );
    assert_eq!(receiver.open(&wrong_direction), Err(ChannelError::Terminal));
    cases.push(());

    let (mut sender, mut receiver) = confirmed_pair();
    let mut corrupt = sender.seal(b"tag").expect("seal");
    if let ChannelFrame::Sealed { ciphertext, .. } = &mut corrupt {
        ciphertext[0] ^= 1;
    }
    assert_eq!(receiver.open(&corrupt), Err(ChannelError::InvalidTag));
    assert_eq!(receiver.open(&corrupt), Err(ChannelError::Terminal));
    cases.push(());

    let (_, mut receiver) = confirmed_pair();
    let unexpected = ChannelFrame::Finished {
        side: Side::Allocator,
        control: vec![1],
        value: [0; 64],
    };
    assert_eq!(
        receiver.open(&unexpected),
        Err(ChannelError::UnexpectedFrame)
    );
    assert_eq!(receiver.open(&unexpected), Err(ChannelError::Terminal));
    cases.push(());

    let (_, mut receiver) = confirmed_pair();
    let undersized = ChannelFrame::Sealed {
        direction: Direction::AllocatorToClaimant,
        counter: 0,
        ciphertext: vec![0; 16],
    };
    assert_eq!(receiver.open(&undersized), Err(ChannelError::MessageSize));
    assert_eq!(receiver.open(&undersized), Err(ChannelError::Terminal));
    cases.push(());

    assert_eq!(cases.len(), 6);
}

#[test]
fn nonce_aad_and_size_bounds_are_exact() {
    let iv: [u8; 12] = (0_u8..12).collect::<Vec<_>>().try_into().expect("iv");
    assert_eq!(
        hex::encode(derive_nonce(iv, 0x0102_0304_0506_0708)),
        "00010203050705030d0f0d03"
    );

    let transcript_hash: [u8; 64] = bytes(
        "bf599dc026a51800c941265721b9dc8b51e36564cc4b9c93aa2bd2e45c581496\
         0f421efb58d83ae9e2427eb2beb32720a640e6380f429b2c703341e611fa0de8",
    )
    .try_into()
    .expect("TH");
    assert_eq!(
        hex::encode(sealed_aad(Direction::AllocatorToClaimant, 0, &transcript_hash).expect("AAD")),
        concat!(
            "a46176016274685840",
            "bf599dc026a51800c941265721b9dc8b51e36564cc4b9c93aa2bd2e45c581496",
            "0f421efb58d83ae9e2427eb2beb32720a640e6380f429b2c703341e611fa0de8",
            "67636f756e7465720069646972656374696f6e00"
        )
    );

    let (mut sender, _) = confirmed_pair();
    assert_eq!(sender.seal(b""), Err(ChannelError::MessageSize));
    assert_eq!(
        sender.seal(&vec![0; MAX_SEALED_PLAINTEXT + 1]),
        Err(ChannelError::MessageSize)
    );
    let largest = sender
        .seal(&vec![0; MAX_SEALED_PLAINTEXT])
        .expect("largest legal plaintext");
    let ChannelFrame::Sealed {
        counter,
        ciphertext,
        ..
    } = largest
    else {
        panic!("sealed frame")
    };
    assert_eq!(counter, 0, "local size errors do not consume a nonce");
    assert_eq!(ciphertext.len(), MAX_SEALED_PLAINTEXT + 16);
}

fn confirmed_pair() -> (
    cbcl_pairing::channel::SecureChannel,
    cbcl_pairing::channel::SecureChannel,
) {
    let (allocator, claimant) = pending_pair();
    let a_finished = allocator.local_finished();
    let b_finished = claimant.local_finished();
    (
        allocator.confirm(&b_finished).expect("confirm A"),
        claimant.confirm(&a_finished).expect("confirm B"),
    )
}
