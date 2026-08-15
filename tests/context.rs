//! Canonical SPEC-072 CPace context and message tests.

use cbcl_pairing::{
    context::{ContextError, PairingContext},
    cpace::{finish, start_pairing, CpaceError},
    wire::{
        decode_channel_frame, decode_cpace_message, encode_channel_frame, encode_cpace_message,
        ChannelFrame, Invitation, Locator, Side,
    },
};

const MAILBOX_ID: [u8; 32] = [0x55; 32];

fn invitation() -> Invitation {
    Invitation {
        application: "example.test/synthetic/v1".into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct(MAILBOX_ID),
        secret: vec![0x31; 16],
        expected_allocator_key: Some([0x11; 32]),
        expected_claimant_key: None,
    }
}

#[test]
fn normative_context_fixes_ci_sid_roles_and_optional_key_identity() {
    let context = PairingContext::derive(&invitation(), MAILBOX_ID).expect("context");
    assert_eq!(context.session_id(), &MAILBOX_ID);
    assert_eq!(
        hex::encode(context.channel_identifier()),
        "87726362636c2d70616972696e672d63692f76310175435041434532353531392d5348413531322d44323178196578616d706c652e746573742f73796e7468657469632f76317568747470733a2f2f72656c61792e6578616d706c65582055555555555555555555555555555555555555555555555555555555555555558269616c6c6f6361746f7268636c61696d616e74"
    );
    assert_eq!(
        hex::encode(context.associated_data(Side::Allocator)),
        "83726362636c2d70616972696e672d61642f763169616c6c6f6361746f7258201111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(
        hex::encode(context.associated_data(Side::Claimant)),
        "83726362636c2d70616972696e672d61642f763168636c61696d616e74f6"
    );
    assert_eq!(
        hex::encode(context.channel_context()),
        "88781e6362636c2d70616972696e672d7075626c69632d636f6e746578742f76310175435041434532353531392d5348413531322d44323178196578616d706c652e746573742f73796e7468657469632f76317568747470733a2f2f72656c61792e6578616d706c655820555555555555555555555555555555555555555555555555555555555555555558201111111111111111111111111111111111111111111111111111111111111111f6"
    );
    assert_eq!(
        PairingContext::derive(&invitation(), [0x99; 32]),
        Err(ContextError::MailboxMismatch)
    );
}

#[test]
fn nested_cpace_message_is_deterministic_and_role_consistent() {
    let (state, message) =
        start_pairing(Side::Allocator, &invitation(), MAILBOX_ID, [0x41; 32]).expect("start");
    drop(state);
    let encoded = encode_cpace_message(&message).expect("message encoding");
    assert_eq!(decode_cpace_message(&encoded), Ok(message.clone()));
    let frame = ChannelFrame::Cpace {
        side: Side::Allocator,
        control: b"signed-control".to_vec(),
        message: encoded.clone(),
    };
    let frame_bytes = encode_channel_frame(&frame).expect("frame");
    assert_eq!(decode_channel_frame(&frame_bytes), Ok(frame));

    let mut wrong = message;
    wrong.side = Side::Claimant;
    let mismatched = ChannelFrame::Cpace {
        side: Side::Allocator,
        control: b"signed-control".to_vec(),
        message: encode_cpace_message(&wrong).expect("wrong role message"),
    };
    assert!(encode_channel_frame(&mismatched).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_cpace_message(&trailing).is_err());
}

#[test]
fn pairing_start_reconstructs_and_checks_the_peer_associated_data() {
    let invitation = invitation();
    let (allocator, allocator_message) =
        start_pairing(Side::Allocator, &invitation, MAILBOX_ID, [0x41; 32]).expect("allocator");
    let (claimant, claimant_message) =
        start_pairing(Side::Claimant, &invitation, MAILBOX_ID, [0x42; 32]).expect("claimant");
    let allocator_key = finish(allocator, &claimant_message).expect("allocator finish");
    let claimant_key = finish(claimant, &allocator_message).expect("claimant finish");
    assert_eq!(allocator_key.as_bytes(), claimant_key.as_bytes());

    let (allocator, _) = start_pairing(Side::Allocator, &invitation, MAILBOX_ID, [0x41; 32])
        .expect("allocator retry");
    let mut wrong_ad = claimant_message;
    wrong_ad.associated_data[0] ^= 1;
    assert!(matches!(
        finish(allocator, &wrong_ad),
        Err(CpaceError::AssociatedData)
    ));
}
