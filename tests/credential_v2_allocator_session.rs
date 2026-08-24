//! SPEC-001 TEST-065 / cbcl-bus TEST-117 allocator durability red gate.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_carrier, decode_frame, CredentialV2AllocatorEffect, CredentialV2AllocatorSession,
        CredentialV2AllocatorSessionInput, CredentialV2BodyVerifier, CredentialV2CheckpointNonce,
        CredentialV2Context, CredentialV2Error, CredentialV2Frame, CredentialV2Kind,
        CredentialV2LogicalBody, CredentialV2Object, CredentialV2Presence,
        CredentialV2PresenceCode, PendingCredentialV2Channel,
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
struct AcceptBodies;

impl CredentialV2BodyVerifier for AcceptBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Ok(())
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

fn assert_restored_reopens_cached_bootstrap_frame(
    checkpoint: &[u8],
    carrier: &[u8],
    generation: u64,
    expected_sequence: u8,
    expected_body: &[u8],
    nonce: [u8; 12],
) {
    let mut restored = CredentialV2AllocatorSession::restore(
        checkpoint,
        &WRAPPING_KEY,
        decode_carrier(carrier).unwrap(),
        generation,
        PROFILE_DIGEST,
        NOW,
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(
        decode_client_message(&restored.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );
    let reopened = restored
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng(nonce),
        )
        .unwrap();
    let commands = sent(&reopened);
    assert!(matches!(
        commands.first(),
        Some(ClientMessage::Open {
            mailbox_id: MAILBOX,
            membership_token: MEMBERSHIP,
        })
    ));
    assert!(matches!(
        commands.get(1),
        Some(ClientMessage::Put { seq, body })
            if *seq == expected_sequence && body == expected_body
    ));
    assert_eq!(commands.len(), 2, "recovery resends only the cached frame");
}

fn assert_restored_reopens_acknowledged_bootstrap_frame(
    checkpoint: &[u8],
    carrier: &[u8],
    generation: u64,
    nonce: [u8; 12],
) {
    let mut restored = CredentialV2AllocatorSession::restore(
        checkpoint,
        &WRAPPING_KEY,
        decode_carrier(carrier).unwrap(),
        generation,
        PROFILE_DIGEST,
        NOW,
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(
        decode_client_message(&restored.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );
    let reopened = restored
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng(nonce),
        )
        .unwrap();
    let commands = sent(&reopened);
    assert!(matches!(
        commands.as_slice(),
        [ClientMessage::Open {
            mailbox_id: MAILBOX,
            membership_token: MEMBERSHIP,
        }]
    ));
}

#[test]
fn allocator_requests_900_and_checkpoints_before_carrier_and_each_cached_frame() {
    let mut allocator = CredentialV2AllocatorSession::new(input(), Box::new(AcceptBodies)).unwrap();
    assert_eq!(
        allocator.receipt_recovery_commitment().unwrap_err(),
        CredentialV2Error::Phase,
    );
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

    let share_pending = allocator
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 0,
                body: cbcl_pairing::credential_v2::encode_frame(&claimant_share).unwrap(),
            }),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x24; 12]),
        )
        .unwrap();
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: 2,
        checkpoint: share_checkpoint,
        carrier: share_carrier,
    }] = share_pending.as_slice()
    else {
        panic!("allocator share must be withheld behind generation two")
    };
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
    assert_restored_reopens_cached_bootstrap_frame(
        share_checkpoint.as_bytes(),
        share_carrier,
        2,
        0,
        allocator_share,
        [0x2a; 12],
    );
    let allocator_share = decode_frame(allocator_share).unwrap();

    let finished_pending = allocator
        .receive(
            &server(ServerMessage::Acknowledged { seq: 0 }),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x25; 12]),
        )
        .unwrap();
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: 3,
        checkpoint: finished_checkpoint,
        carrier: finished_carrier,
    }] = finished_pending.as_slice()
    else {
        panic!("allocator Finished must be withheld behind generation three")
    };
    let finished_effects = allocator.checkpoint_persisted(3).unwrap();
    let finished_commands = sent(&finished_effects);
    let ClientMessage::Put {
        seq: 1,
        body: allocator_finished,
    } = &finished_commands[0]
    else {
        panic!("allocator Finished is exact relay sequence one")
    };
    assert_restored_reopens_cached_bootstrap_frame(
        finished_checkpoint.as_bytes(),
        finished_carrier,
        3,
        1,
        allocator_finished,
        [0x2b; 12],
    );
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
    let mut claimant_channel = claimant_pending.confirm(&allocator_finished).unwrap();

    let finished_acknowledged = allocator
        .receive(
            &server(ServerMessage::Acknowledged { seq: 1 }),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x26; 12]),
        )
        .unwrap();
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: 4,
        checkpoint: acknowledged_checkpoint,
        carrier: acknowledged_carrier,
    }] = finished_acknowledged.as_slice()
    else {
        panic!("acknowledged allocator Finished must be sealed at generation four")
    };
    assert!(allocator.checkpoint_persisted(4).unwrap().is_empty());
    assert_restored_reopens_acknowledged_bootstrap_frame(
        acknowledged_checkpoint.as_bytes(),
        acknowledged_carrier,
        4,
        [0x2c; 12],
    );

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
    let receipt_recovery_commitment = allocator.receipt_recovery_commitment().unwrap();
    assert_ne!(receipt_recovery_commitment, [0_u8; 32]);
    assert_eq!(
        allocator.receipt_recovery_commitment().unwrap(),
        receipt_recovery_commitment,
    );

    let intent_digest = [0x51; 32];
    let offer = CredentialV2Object::new(CredentialV2Kind::Offer, intent_digest, vec![0xa0])
        .expect("bounded offer object");
    let offer_pending = allocator
        .prepare_application_object(
            &offer,
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x52; 12]),
        )
        .unwrap();
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: 6,
        checkpoint,
        carrier: checkpoint_carrier,
    }] = offer_pending.as_slice()
    else {
        panic!("the cached offer must be sealed before release")
    };
    assert_eq!(decode_carrier(checkpoint_carrier).unwrap(), carrier);
    let mut restored = CredentialV2AllocatorSession::restore(
        checkpoint.as_bytes(),
        &WRAPPING_KEY,
        carrier.clone(),
        6,
        PROFILE_DIGEST,
        NOW,
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(restored.presence_code(), None);
    assert_eq!(
        decode_client_message(&restored.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );
    let reopened = restored
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x56; 12]),
        )
        .unwrap();
    let reopened_commands = sent(&reopened);
    assert!(matches!(
        reopened_commands[0],
        ClientMessage::Open {
            mailbox_id: MAILBOX,
            membership_token: MEMBERSHIP,
        }
    ));
    let ClientMessage::Put {
        seq: 2,
        body: reopened_offer,
    } = &reopened_commands[1]
    else {
        panic!("restart must resend only the cached offer frame")
    };
    let offer_effects = allocator.checkpoint_persisted(6).unwrap();
    let offer_commands = sent(&offer_effects);
    let [ClientMessage::Put {
        seq: 2,
        body: sealed_offer,
    }] = offer_commands.as_slice()
    else {
        panic!("offer is the exact next relay frame")
    };
    assert_eq!(reopened_offer, sealed_offer);
    let sealed_offer = decode_frame(sealed_offer).unwrap();
    assert_eq!(
        claimant_channel.open(&sealed_offer).unwrap(),
        offer.as_bytes()
    );

    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Acknowledged { seq: 2 }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x53; 12]),
            )
            .unwrap(),
        7,
    );
    assert!(allocator.checkpoint_persisted(7).unwrap().is_empty());

    let decision_body = cbor2::to_canonical_vec(&ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("carrierCeremonyId".into()),
            ciborium::Value::Bytes([0x17; 32].to_vec()),
        ),
        (
            ciborium::Value::Text("decision".into()),
            ciborium::Value::Text("approve".into()),
        ),
        (
            ciborium::Value::Text("offerCoreDigest".into()),
            ciborium::Value::Bytes([0x54; 32].to_vec()),
        ),
        (
            ciborium::Value::Text("predecessorDigest".into()),
            ciborium::Value::Bytes(offer.content_hash().to_vec()),
        ),
    ]))
    .unwrap();
    let decision = CredentialV2Object::new(
        CredentialV2Kind::IntentApprove,
        intent_digest,
        decision_body,
    )
    .unwrap();
    let claimant_frame = claimant_channel.seal(decision.as_bytes()).unwrap();
    one_checkpoint(
        allocator
            .receive(
                &server(ServerMessage::Frame {
                    peer_seq: 2,
                    body: cbcl_pairing::credential_v2::encode_frame(&claimant_frame).unwrap(),
                }),
                NOW,
                CredentialV2CheckpointNonce::from_csprng([0x55; 12]),
            )
            .unwrap(),
        8,
    );
    let decision_effects = allocator.checkpoint_persisted(8).unwrap();
    assert!(matches!(
        sent(&decision_effects)[0],
        ClientMessage::Ack { peer_seq: 2 }
    ));
    assert!(matches!(
        &decision_effects[1],
        CredentialV2AllocatorEffect::ReceivedObject { object } if object == &decision
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
            CredentialV2AllocatorSession::new(input(), Box::new(AcceptBodies)).unwrap();
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

#[test]
fn allocator_restores_the_bound_membership_and_only_the_cached_frame() {
    let mut allocator = CredentialV2AllocatorSession::new(input(), Box::new(AcceptBodies)).unwrap();
    allocator
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x61; 12]),
        )
        .unwrap();
    let allocated = allocator
        .receive(
            &server(ServerMessage::AllocatedV2 {
                mailbox_id: MAILBOX,
                membership_token: MEMBERSHIP,
                expires_at: EXPIRY,
            }),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x62; 12]),
        )
        .unwrap();
    let [CredentialV2AllocatorEffect::Checkpoint {
        generation: 1,
        checkpoint,
        carrier,
    }] = allocated.as_slice()
    else {
        panic!("allocation must be one checkpoint")
    };
    let carrier = decode_carrier(carrier).unwrap();
    let checkpoint = checkpoint.as_bytes().to_vec();

    let mut restored = CredentialV2AllocatorSession::restore(
        &checkpoint,
        &WRAPPING_KEY,
        carrier.clone(),
        1,
        PROFILE_DIGEST,
        NOW,
        Box::new(AcceptBodies),
    )
    .unwrap();
    assert_eq!(
        restored.presence_code(),
        Some(CredentialV2PresenceCode::new(CPACE_SECRET, CLAIM_TOKEN).to_string()),
    );
    assert_eq!(
        decode_client_message(&restored.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );
    let reopened = restored
        .receive(
            &server(ServerMessage::Welcome),
            NOW,
            CredentialV2CheckpointNonce::from_csprng([0x63; 12]),
        )
        .unwrap();
    assert_eq!(
        sent(&reopened),
        vec![ClientMessage::Open {
            mailbox_id: MAILBOX,
            membership_token: MEMBERSHIP,
        }],
    );

    assert!(CredentialV2AllocatorSession::restore(
        &checkpoint,
        &WRAPPING_KEY,
        carrier,
        1,
        [0xff; 32],
        NOW,
        Box::new(AcceptBodies),
    )
    .is_err());
}
