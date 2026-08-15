//! Minimal, non-production example of the application-owned CPace entry point.

use cbcl_pairing::{
    context::PairingContext,
    cpace::start_pairing,
    wire::{encode_cpace_message, encode_invitation, Invitation, Locator, Side},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mailbox_id = [0x55; 32];
    let invitation = Invitation {
        application: "example.test/synthetic/v1".into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct(mailbox_id),
        // Fixed values make an example reproducible. Production uses fresh
        // OS-backed CSPRNG output for both the secret and the scalar.
        secret: vec![0x31; 16],
        expected_allocator_key: None,
        expected_claimant_key: None,
    };

    let invitation_bytes = encode_invitation(&invitation)?;
    let context = PairingContext::derive(&invitation, mailbox_id)?;
    let (_state, message) = start_pairing(Side::Allocator, &invitation, mailbox_id, [0x41; 32])?;
    let message_bytes = encode_cpace_message(&message)?;

    // The secret is deliberately never printed.
    println!(
        "invitation={} CI={} sid={} CPace-message={}",
        invitation_bytes.len(),
        context.channel_identifier().len(),
        context.session_id().len(),
        message_bytes.len()
    );
    Ok(())
}
