//! SPEC-001 TEST-065 / cbcl-bus TEST-117 allocator durability red gate.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, decode_frame, CredentialV2AllocatorEffect, CredentialV2AllocatorSession,
        CredentialV2AllocatorSessionInput, CredentialV2BodyVerifier, CredentialV2CheckpointNonce,
        CredentialV2Context, CredentialV2Error, CredentialV2Frame, CredentialV2LogicalBody,
        CredentialV2Presence, PendingCredentialV2Channel,
    },
    wire::{decode_client_message, encode_server_message, ClientMessage, ServerMessage, Side},
};

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 900;
const MAILBOX: [u8; 32] = [0x11; 32];
const CLAIM_TOKEN: [u8; 16] = [0x12; 16];
const CPACE_SECRET: [u8; 16] = [0x13; 16];
const PROFILE_DIGEST: [u8; 32] = [0x14; 32];
const MEMBERSHIP: [u8; 32] = [0x15; 32];
const WRAPPING_KEY: [u8; 32] = [0x16; 32];

#[derive(Debug)]
struct RefuseBodies;

impl CredentialV2BodyVerifier for RefuseBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Err(CredentialV2Error::Schema)
    }
}

fn input() -> CredentialV2AllocatorSessionInput {
    CredentialV2AllocatorSessionInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: MAILBOX,
        carrier_ceremony_id: [0x17; 32],
        carrier_nonce: [0x18; 32],
        cpace_secret: CPACE_SECRET,
        claim_token: CLAIM_TOKEN,
        cpace_scalar: [0x19; 32],
        profile_digest: PROFILE_DIGEST,
        expected_allocator_key: Some([0x1a; 32]),
        checkpoint_wrapping_key: WRAPPING_KEY,
    }
}

fn server(message: ServerMessage) -> Vec<u8> {
    encode_server_message(&message).unwrap()
}

fn one_checkpoint(effects: Vec<CredentialV2AllocatorEffect>, generation: u64) -> Vec<u8> {
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: actual,
        checkpoint,
        carrier,
    }] = effects.as_slice()
    else {
        panic!("transition released something before its checkpoint: {effects:?}")
    };
    assert_eq!(*actual, generation);
    assert!(!checkpoint.as_bytes().is_empty());
    assert!(
        !carrier.is_empty(),
        "recovery persists the recognised carrier"
    );
    carrier.clone()
}

fn sent(effects: &[CredentialV2AllocatorEffect]) -> Vec<ClientMessage> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            CredentialV2AllocatorEffect::Send(bytes) => Some(decode_client_message(bytes).unwrap()),
            _ => None,
        })
        .collect()
}

#[test]
fn allocator_requests_900_and_checkpoints_before_carrier_and_each_cached_frame() {
    let mut allocator = CredentialV2AllocatorSession::new(input(), Box::new(RefuseBodies)).unwrap();
    assert_eq!(
        decode_client_message(&allocator.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );

    let effects = allocator
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x21; 12]),
        )
        .unwrap();
    assert_eq!(
        sent(&effects),
        vec![ClientMessage::AllocateV2 {
            mailbox_id: MAILBOX,
            claim_commitment: cbcl_pairing::wire::claim_commitment(
                MAILBOX,
                &cbcl_pairing::wire::ClaimToken::new(CLAIM_TOKEN),
            ),
            ttl_seconds: Some(900),
        }],
    );

    let carrier_bytes = one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::AllocatedV2 {
                    mailbox_id: MAILBOX,
                    membership_token: MEMBERSHIP,
                    expires_at: EXPIRY,
                }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x22; 12]),
            )
            .unwrap(),
        1,
    );
    let carrier = decode_carrier(&carrier_bytes).unwrap();
    let effects = allocator.checkpoint_persisted(1).unwrap();
    assert!(matches!(
        effects.as_slice(),
        [CredentialV2AllocatorEffect::PendingAllocation { carrier: value }]
            if value == &carrier_bytes
    ));

    let context = CredentialV2Context::derive(&carrier, PROFILE_DIGEST).unwrap();
    let claimant_presence = CredentialV2Presence::new(CPACE_SECRET, CLAIM_TOKEN);
    let (claimant_state, claimant_share) = context
        .start_cpace(Side::Claimant, &claimant_presence, [0x23; 32])
        .unwrap();
    let claimant_share = CredentialV2Frame::cpace(&claimant_share).unwrap();

    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Frame {
                    peer_seq: 0,
                    body: cbcl_pairing::credential_v2::encode_frame(&claimant_share).unwrap(),
                }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x24; 12]),
            )
            .unwrap(),
        2,
    );
    let share_effects = allocator.checkpoint_persisted(2).unwrap();
    let share_commands = sent(&share_effects);
    assert!(matches!(
        share_commands[0],
        ClientMessage::Ack { peer_seq: 0 }
    ));
    let ClientMessage::Put {
        seq: 0,
        body: allocator_share,
    } = &share_commands[1]
    else {
        panic!("allocator share is exact relay sequence zero")
    };
    let allocator_share = decode_frame(allocator_share).unwrap();

    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Acknowledged { seq: 0 }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x25; 12]),
            )
            .unwrap(),
        3,
    );
    let finished_effects = allocator.checkpoint_persisted(3).unwrap();
    let finished_commands = sent(&finished_effects);
    let ClientMessage::Put {
        seq: 1,
        body: allocator_finished,
    } = &finished_commands[0]
    else {
        panic!("allocator Finished is exact relay sequence one")
    };
    let allocator_finished = decode_frame(allocator_finished).unwrap();

    let claimant_isk = cpace::finish(
        claimant_state,
        allocator_share.cpace_message().expect("allocator CPace"),
    )
    .unwrap();
    let claimant_pending = PendingCredentialV2Channel::new(
        Side::Claimant,
        claimant_isk,
        context.public_context(),
        &cbcl_pairing::credential_v2::encode_frame(&allocator_share).unwrap(),
        &cbcl_pairing::credential_v2::encode_frame(&claimant_share).unwrap(),
    )
    .unwrap();
    let claimant_finished = claimant_pending.local_finished_frame();
    claimant_pending.confirm(&allocator_finished).unwrap();

    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Acknowledged { seq: 1 }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x26; 12]),
            )
            .unwrap(),
        4,
    );
    assert!(allocator.checkpoint_persisted(4).unwrap().is_empty());

    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Frame {
                    peer_seq: 1,
                    body: cbcl_pairing::credential_v2::encode_frame(&claimant_finished).unwrap(),
                }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x27; 12]),
            )
            .unwrap(),
        5,
    );
    let established = allocator.checkpoint_persisted(5).unwrap();
    assert!(matches!(
        established.as_slice(),
        [CredentialV2AllocatorEffect::Send(_), CredentialV2AllocatorEffect::Established {
            transcript_hash
        }] if transcript_hash.len() == 64
    ));
    assert!(matches!(
        sent(&established)[0],
        ClientMessage::Ack { peer_seq: 1 }
    ));
}

#[test]
fn carrier_and_checkpoint_are_withheld_on_allocation_mismatch_or_expiry() {
    for response in [
        ServerMessage::AllocatedV2 {
            mailbox_id: [0xff; 32],
            membership_token: MEMBERSHIP,
            expires_at: EXPIRY,
        },
        ServerMessage::AllocatedV2 {
            mailbox_id: MAILBOX,
            membership_token: MEMBERSHIP,
            expires_at: NOW,
        },
    ] {
        let mut allocator =
            CredentialV2AllocatorSession::new(input(), Box::new(RefuseBodies)).unwrap();
        allocator
            .receive(
                &server(ServerMessage::Welcome),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x31; 12]),
            )
            .unwrap();
        assert!(allocator
            .receive(
                &server(response),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x32; 12]),
            )
            .is_err());
    }
}
