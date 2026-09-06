//! SPEC-078 REQ-003/005/006/007; TEST-003/006/007; SPEC-001 TEST-063/065.
use cbcl_pairing::{
    credential_v2::{
        decode_carrier, decode_frame, encode_frame, CredentialV2AllocatorEffect as Effect,
        CredentialV2AllocatorMode as Mode, CredentialV2AllocatorSession as Session,
        CredentialV2AllocatorSessionInput as Input, CredentialV2BodyVerifier, CredentialV2Carrier,
        CredentialV2CheckpointNonce as Nonce, CredentialV2Context, CredentialV2Error as Error,
        CredentialV2Frame, CredentialV2Handoff, CredentialV2Kind, CredentialV2LogicalBody,
        CredentialV2ManualBootstrap as Bootstrap, CredentialV2ManualWords as Words,
        CredentialV2Object, CredentialV2Presence, CredentialV2PresenceCode,
    },
    wire::{decode_client_message, encode_server_message, ClientMessage, ServerMessage, Side},
};
const NOW: u64 = 1_800_000_000;
const KEY: [u8; 32] = [0x16; 32];
const PD: [u8; 32] = [0x17; 32];
const T: [u8; 16] = [0x15; 16];
const M: [u8; 32] = [0x11; 32];
#[derive(Debug)]
struct NoBodies;
impl CredentialV2BodyVerifier for NoBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), Error> {
        panic!("no application call is permitted before Finished")
    }
}
fn input(mode: Mode) -> Input {
    Input {
        mode,
        application_context: "https://a.b/a".into(),
        relay_origin: "https://r".into(),
        mailbox_id: M,
        carrier_ceremony_id: [0x12; 32],
        carrier_nonce: [0x13; 32],
        // Deliberately also a valid Full random value: prefix never selects mode.
        cpace_secret: *Words::from_csprng([0x12, 0x34, 0x56, 0x78]).cpace_secret(),
        claim_token: T,
        cpace_scalar: [0x18; 32],
        profile_digest: PD,
        expected_allocator_key: Some([0x19; 32]),
        checkpoint_wrapping_key: KEY,
    }
}
fn receive(s: &mut Session, message: ServerMessage, nonce: u8) -> Result<Vec<Effect>, Error> {
    s.receive(
        &encode_server_message(&message).unwrap(),
        NOW,
        Nonce::from_csprng([nonce; 12]),
    )
}
fn checkpoint(effects: &[Effect], generation: u64) -> (Vec<u8>, CredentialV2Carrier) {
    let [Effect::Checkpoint {
        checkpoint,
        carrier,
        generation: actual,
    }] = effects
    else {
        panic!("checkpoint must be the only effect, before any Ack or response: {effects:?}")
    };
    assert_eq!(*actual, generation);
    (
        checkpoint.as_bytes().to_vec(),
        decode_carrier(carrier).unwrap(),
    )
}
fn sent(effects: &[Effect]) -> Vec<ClientMessage> {
    effects
        .iter()
        .map(|e| match e {
            Effect::Send(b) => decode_client_message(b).unwrap(),
            _ => panic!("unexpected effect {e:?}"),
        })
        .collect()
}
fn allocate(mode: Mode) -> (Session, Vec<u8>, CredentialV2Carrier) {
    let mut s = Session::new(input(mode), Box::new(NoBodies)).unwrap();
    assert!(s.handoff_text().unwrap().is_none());
    assert!(s.manual_transfer_text().unwrap().is_none());
    assert_eq!(
        sent(&receive(&mut s, ServerMessage::Welcome, 1).unwrap()),
        vec![ClientMessage::AllocateV2 {
            mailbox_id: M,
            claim_commitment: cbcl_pairing::wire::claim_commitment(
                M,
                &cbcl_pairing::wire::ClaimToken::new(T)
            ),
            ttl_seconds: Some(900)
        }]
    );
    let effects = receive(
        &mut s,
        ServerMessage::AllocatedV2 {
            mailbox_id: M,
            membership_token: [0x20; 32],
            expires_at: NOW + 900,
        },
        2,
    )
    .unwrap();
    let (sealed, carrier) = checkpoint(&effects, 1);
    let [Effect::PendingAllocation { .. }] = s.checkpoint_persisted(1).unwrap().as_slice() else {
        panic!("hub allocation follows persistence")
    };
    (s, sealed, carrier)
}
fn restore(
    sealed: &[u8],
    carrier: &CredentialV2Carrier,
    generation: u64,
    mode: Mode,
    scalar: [u8; 32],
) -> Result<Session, Error> {
    Session::restore(
        sealed,
        &KEY,
        carrier.clone(),
        generation,
        PD,
        NOW,
        mode,
        scalar,
        Box::new(NoBodies),
    )
}
fn share(carrier: &CredentialV2Carrier, c: [u8; 16], scalar: u8) -> CredentialV2Frame {
    let context = CredentialV2Context::derive(carrier, PD).unwrap();
    let (_, message) = context
        .start_cpace(
            Side::Claimant,
            &CredentialV2Presence::new(c, T),
            [scalar; 32],
        )
        .unwrap();
    CredentialV2Frame::cpace(&message).unwrap()
}
fn frame(share: &CredentialV2Frame) -> ServerMessage {
    ServerMessage::Frame {
        peer_seq: 0,
        body: encode_frame(share).unwrap(),
    }
}
fn put(effects: &[Effect]) -> Vec<u8> {
    let messages = sent(effects);
    let ClientMessage::Put { seq: 0, body } = messages.last().unwrap() else {
        panic!("expected share")
    };
    body.clone()
}

#[test]
fn restored_duplicate_stored_ack_is_inert_without_weakening_expiry_or_pending_gates() {
    for mode in [Mode::Full, Mode::Manual] {
        let (mut original, _, carrier) = allocate(mode);
        let peer = share(&carrier, input(mode).cpace_secret, 0x31);
        let effects = receive(&mut original, frame(&peer), 3).unwrap();
        let (bound, _) = checkpoint(&effects, 2);
        let exact = sent(&original.checkpoint_persisted(2).unwrap());
        let mut restored = restore(&bound, &carrier, 2, mode, [0x71; 32]).unwrap();
        let reopened = sent(&receive(&mut restored, ServerMessage::Welcome, 4).unwrap());
        assert_eq!(reopened[1], exact[1]);
        assert_eq!(
            sent(&receive(&mut restored, frame(&peer), 5).unwrap()),
            exact
        );
        // Open/replay released the same Put twice, so both stored acknowledgements
        // are real possible relay responses. The second must not advance again.
        let acknowledged =
            receive(&mut restored, ServerMessage::Acknowledged { seq: 0 }, 6).unwrap();
        let (finished, _) = checkpoint(&acknowledged, 3);
        assert!(
            matches!(
                receive(&mut restored, ServerMessage::Acknowledged { seq: 0 }, 7),
                Err(Error::Phase)
            ),
            "the pending persistence gate still precedes duplicate recognition"
        );
        restored.checkpoint_persisted(3).unwrap();
        assert!(
            receive(&mut restored, ServerMessage::Acknowledged { seq: 0 }, 7)
                .unwrap()
                .is_empty()
        );
        // The ignored call did not consume nonce 7 or increment the generation.
        let next = receive(&mut restored, ServerMessage::Acknowledged { seq: 1 }, 7).unwrap();
        checkpoint(&next, 4);
        restored.checkpoint_persisted(4).unwrap();
        for seq in [0, 1] {
            assert!(
                receive(&mut restored, ServerMessage::Acknowledged { seq }, 8)
                    .unwrap()
                    .is_empty()
            );
        }
        let mut unknown = restore(&finished, &carrier, 3, mode, [0x72; 32]).unwrap();
        assert!(matches!(
            receive(&mut unknown, ServerMessage::Acknowledged { seq: 2 }, 8),
            Err(Error::Counter)
        ));
        let mut expired = restore(&finished, &carrier, 3, mode, [0x73; 32]).unwrap();
        assert!(matches!(
            expired.receive(
                &encode_server_message(&ServerMessage::Acknowledged { seq: 0 }).unwrap(),
                carrier.relay_expires_at(),
                Nonce::from_csprng([9; 12]),
            ),
            Err(Error::Expired)
        ));
        assert!(expired.bootstrap_phase().is_none());
    }
}

#[test]
fn pre_peer_restore_uses_each_explicit_shell_scalar_in_both_modes() {
    for mode in [Mode::Full, Mode::Manual] {
        let (_, sealed, carrier) = allocate(mode);
        let peer = share(&carrier, input(mode).cpace_secret, 0x31);
        let context = CredentialV2Context::derive(&carrier, PD).unwrap();
        let mut outputs = Vec::new();
        for scalar in [[0x42; 32], [0x53; 32], [0x64; 32]] {
            let mut restored = restore(&sealed, &carrier, 1, mode, scalar).unwrap();
            assert_eq!(restored.bootstrap_mode(), Some(mode));
            assert_eq!(
                sent(&receive(&mut restored, ServerMessage::Welcome, 0x40).unwrap()).len(),
                1
            );
            let effects = receive(&mut restored, frame(&peer), 0x41).unwrap();
            checkpoint(&effects, 2);
            assert!(restored.start().is_err());
            assert!(receive(&mut restored, frame(&peer), 0x42).is_err());
            assert!(restored.checkpoint_persisted(1).is_err());
            let out = put(&restored.checkpoint_persisted(2).unwrap());
            let (_, expected) = context
                .start_cpace(
                    Side::Allocator,
                    &CredentialV2Presence::new(input(mode).cpace_secret, T),
                    scalar,
                )
                .unwrap();
            assert_eq!(
                decode_frame(&out).unwrap(),
                CredentialV2Frame::cpace(&expected).unwrap()
            );
            outputs.push(out);
        }
        assert_ne!(outputs[0], outputs[1]);
        assert_ne!(outputs[1], outputs[2]);
    }
}

#[test]
fn wrong_valid_phrase_pins_one_peer_across_every_ack_response_crash_boundary() {
    let (mut session, before, carrier) = allocate(Mode::Manual);
    let wrong = share(&carrier, *Words::from_csprng([0; 4]).cpace_secret(), 0x33);
    let correct = share(&carrier, input(Mode::Manual).cpace_secret, 0x44);
    let same_password_new_share = share(&carrier, *Words::from_csprng([0; 4]).cpace_secret(), 0x55);
    let effects = receive(&mut session, frame(&wrong), 3).unwrap();
    let (bound, _) = checkpoint(&effects, 2);
    // Crash before persistence: no output was released. Old durable state may bind anew.
    let mut pre = restore(&before, &carrier, 1, Mode::Manual, [0x71; 32]).unwrap();
    let effects = receive(&mut pre, frame(&correct), 4).unwrap();
    checkpoint(&effects, 2); // still no Ack/Put, and no second released online attempt
    drop(pre);
    let exact = sent(&session.checkpoint_persisted(2).unwrap());
    assert!(matches!(
        exact.as_slice(),
        [
            ClientMessage::Ack { peer_seq: 0 },
            ClientMessage::Put { seq: 0, .. }
        ]
    ));
    // One durable snapshot covers crash after persistence, before/after Ack and before/after Put.
    for boundary in [
        "after persist",
        "before Ack",
        "after Ack",
        "before reply",
        "after reply",
    ] {
        for scalar in [[0x71; 32], [0x82; 32]] {
            let mut restored = restore(&bound, &carrier, 2, Mode::Manual, scalar).unwrap();
            assert!(restored.presence_code().is_none());
            assert!(restored.manual_transfer_text().unwrap().is_none());
            let reopen = sent(&receive(&mut restored, ServerMessage::Welcome, 5).unwrap());
            assert!(matches!(reopen[0], ClientMessage::Open { .. }));
            assert_eq!(reopen[1], exact[1], "{boundary}");
            assert_eq!(
                sent(&receive(&mut restored, frame(&wrong), 6).unwrap()),
                exact,
                "{boundary}"
            );
            assert_eq!(
                sent(&receive(&mut restored, frame(&wrong), 7).unwrap()),
                exact,
                "deterministic replays do not spend another attempt"
            );
            for other in [&correct, &same_password_new_share] {
                let mut r = restore(&bound, &carrier, 2, Mode::Manual, scalar).unwrap();
                assert!(receive(&mut r, frame(other), 8).is_err());
                assert!(r.bootstrap_phase().is_none());
                assert!(r.manual_transfer_text().unwrap().is_none());
                assert!(receive(&mut r, frame(&wrong), 9).is_err());
                let object =
                    CredentialV2Object::new(CredentialV2Kind::Offer, [1; 32], vec![0xa0]).unwrap();
                assert!(r
                    .prepare_application_object(&object, NOW, Nonce::from_csprng([10; 12]))
                    .is_err());
            }
        }
    }
    // Once the cached share is acknowledged, the exact retained scalar derives Finished.
    let mut outputs = Vec::new();
    for scalar in [[0x71; 32], [0x82; 32]] {
        let mut restored = restore(&bound, &carrier, 2, Mode::Manual, scalar).unwrap();
        let effects = receive(&mut restored, ServerMessage::Acknowledged { seq: 0 }, 11).unwrap();
        let (finished, _) = checkpoint(&effects, 3);
        let expected = sent(&restored.checkpoint_persisted(3).unwrap());
        let mut restored = restore(&finished, &carrier, 3, Mode::Manual, [0x93; 32]).unwrap();
        assert_eq!(
            &sent(&receive(&mut restored, ServerMessage::Welcome, 12).unwrap())[1..],
            expected
        );
        assert!(receive(&mut restored, frame(&correct), 13).is_err());
        outputs.push(expected);
    }
    assert_eq!(outputs[0], outputs[1]);
}

#[test]
fn explicit_mode_controls_all_exporters_even_for_full_c_with_manual_prefix() {
    let (manual, sealed, carrier) = allocate(Mode::Manual);
    assert_eq!(manual.bootstrap_mode(), Some(Mode::Manual));
    assert!(manual.presence_code().is_none());
    assert_eq!(manual.handoff_text().unwrap_err(), Error::Phase);
    let (bootstrap, phrase) = manual.manual_transfer_text().unwrap().unwrap();
    let (recovered, presence) = Bootstrap::recognise_pair(&bootstrap, &phrase, NOW).unwrap();
    assert_eq!(carrier, recovered);
    assert_eq!(
        presence.into_presence().cpace_secret(),
        &input(Mode::Manual).cpace_secret
    );
    assert!(restore(&sealed, &carrier, 1, Mode::Full, [1; 32]).is_err());
    assert!(restore(&sealed, &carrier, 2, Mode::Manual, [1; 32]).is_err());
    let (full, sealed, carrier) = allocate(Mode::Full);
    assert_eq!(full.bootstrap_mode(), Some(Mode::Full));
    assert!(full.manual_transfer_text().is_err());
    assert_eq!(
        full.presence_code().unwrap(),
        CredentialV2PresenceCode::new(input(Mode::Full).cpace_secret, T).to_string()
    );
    let handoff: CredentialV2Handoff = full.handoff_text().unwrap().unwrap().parse().unwrap();
    assert_eq!(
        handoff.into_parts().1.into_presence().cpace_secret(),
        &input(Mode::Full).cpace_secret
    );
    assert!(restore(&sealed, &carrier, 1, Mode::Manual, [1; 32]).is_err());
    let mut arbitrary = input(Mode::Full);
    arbitrary.cpace_secret = [0x81; 16];
    assert!(Session::new(arbitrary, Box::new(NoBodies)).is_ok());
    let mut wrong_mapping = input(Mode::Manual);
    wrong_mapping.cpace_secret = [0x81; 16];
    assert!(Session::new(wrong_mapping, Box::new(NoBodies)).is_err());
}

#[test]
fn expired_replay_and_every_terminal_input_export_nothing() {
    for malformed in [false, true] {
        let (mut s, _, _) = allocate(Mode::Manual);
        let bytes = if malformed {
            vec![0]
        } else {
            encode_server_message(&ServerMessage::Closed(
                cbcl_pairing::wire::CloseReason::Closed,
            ))
            .unwrap()
        };
        let result = s.receive(&bytes, NOW, Nonce::from_csprng([3; 12]));
        if malformed {
            assert!(result.is_err());
        } else {
            assert!(matches!(result.unwrap().as_slice(), [Effect::Terminal]));
        }
        assert!(s.presence_code().is_none());
        assert!(s.handoff_text().unwrap().is_none());
        assert!(s.manual_transfer_text().unwrap().is_none());
        assert!(s.start().is_err());
    }
    let (mut s, _, carrier) = allocate(Mode::Manual);
    let peer = share(&carrier, input(Mode::Manual).cpace_secret, 0x31);
    receive(&mut s, frame(&peer), 3).unwrap();
    s.checkpoint_persisted(2).unwrap();
    assert!(s
        .receive(
            &encode_server_message(&frame(&peer)).unwrap(),
            NOW + 900,
            Nonce::from_csprng([4; 12])
        )
        .is_err());
    assert!(s.manual_transfer_text().unwrap().is_none());
}

#[test]
fn checksum_valid_wrong_phrase_fails_both_finished_values_without_application_effects() {
    use cbcl_pairing::{cpace, credential_v2::PendingCredentialV2Channel};
    let (mut s, _, carrier) = allocate(Mode::Manual);
    let context = CredentialV2Context::derive(&carrier, PD).unwrap();
    let wrong = CredentialV2Presence::new(*Words::from_csprng([0; 4]).cpace_secret(), T);
    let (state, message) = context
        .start_cpace(Side::Claimant, &wrong, [0x31; 32])
        .unwrap();
    let peer = CredentialV2Frame::cpace(&message).unwrap();
    checkpoint(&receive(&mut s, frame(&peer), 3).unwrap(), 2);
    let local_bytes = put(&s.checkpoint_persisted(2).unwrap());
    let local = decode_frame(&local_bytes).unwrap();
    let isk = cpace::finish(state, local.cpace_message().unwrap()).unwrap();
    let claimant = PendingCredentialV2Channel::new(
        Side::Claimant,
        isk,
        context.public_context(),
        &local_bytes,
        &encode_frame(&peer).unwrap(),
    )
    .unwrap();
    let claimant_finished = claimant.local_finished_frame();
    checkpoint(
        &receive(&mut s, ServerMessage::Acknowledged { seq: 0 }, 4).unwrap(),
        3,
    );
    let commands = sent(&s.checkpoint_persisted(3).unwrap());
    let ClientMessage::Put { seq: 1, body } = &commands[0] else {
        panic!("Finished")
    };
    assert!(claimant.confirm(&decode_frame(body).unwrap()).is_err());
    checkpoint(
        &receive(&mut s, ServerMessage::Acknowledged { seq: 1 }, 5).unwrap(),
        4,
    );
    assert!(s.checkpoint_persisted(4).unwrap().is_empty());
    assert!(receive(
        &mut s,
        ServerMessage::Frame {
            peer_seq: 1,
            body: encode_frame(&claimant_finished).unwrap()
        },
        6
    )
    .is_err());
    assert!(s.transcript_hash().is_none());
    assert!(s.bootstrap_phase().is_none());
    assert!(s.manual_transfer_text().unwrap().is_none());
}

#[test]
fn closure_inspection_authenticates_expired_bootstrap_without_live_authority() {
    use cbcl_pairing::credential_v2::{
        CredentialV2AllocatorBootstrapPhase as Phase,
        CredentialV2AllocatorCheckpointInspection as Inspection,
    };
    for mode in [Mode::Full, Mode::Manual] {
        let (mut live, allocated, carrier) = allocate(mode);
        let peer = share(&carrier, input(mode).cpace_secret, 0x41);
        let pending = receive(&mut live, frame(&peer), 0x51).unwrap();
        let (bound, _) = checkpoint(&pending, 2);
        for (sealed, generation, phase) in [
            (&allocated, 1, Phase::Allocated),
            (&bound, 2, Phase::ShareSent),
        ] {
            for now in [NOW, NOW + 899, NOW + 900, NOW + 901, u64::MAX] {
                let view = Inspection::inspect(
                    sealed,
                    &KEY,
                    &carrier,
                    generation,
                    PD,
                    now,
                    mode,
                    Box::new(NoBodies),
                )
                .unwrap();
                assert_eq!(view.bootstrap_mode(), Some(mode));
                assert_eq!(view.bootstrap_phase(), Some(phase));
                assert_eq!(view.endpoint_phase(), None);
                assert_eq!(view.transcript_hash(), None);
                assert_eq!(view.receipt_recovery_commitment(), None);
                assert!(view.last_received_object().is_none());
                assert_eq!(view.is_expired(), now >= NOW + 900);
                assert_eq!(
                    format!("{view:?}"),
                    "CredentialV2AllocatorCheckpointInspection([REDACTED])"
                );
                let restored = Session::restore(
                    sealed,
                    &KEY,
                    carrier.clone(),
                    generation,
                    PD,
                    now,
                    mode,
                    [0x61; 32],
                    Box::new(NoBodies),
                );
                assert_eq!(
                    restored.is_ok(),
                    now < NOW + 900,
                    "inspection cannot alter live expiry"
                );
            }
            let other = if mode == Mode::Full {
                Mode::Manual
            } else {
                Mode::Full
            };
            for (key, profile, gen, expected_mode) in [
                ([0xff; 32], PD, generation, mode),
                (KEY, [0xff; 32], generation, mode),
                (KEY, PD, 0, mode),
                (KEY, PD, generation + 1, mode),
                (KEY, PD, generation, other),
            ] {
                assert!(Inspection::inspect(
                    sealed,
                    &key,
                    &carrier,
                    gen,
                    profile,
                    NOW + 901,
                    expected_mode,
                    Box::new(NoBodies)
                )
                .is_err());
            }
            let template = cbcl_pairing::credential_v2::CredentialV2CarrierInput {
                application_context: carrier.application_context().into(),
                relay_origin: carrier.relay_origin().into(),
                mailbox_id: *carrier.mailbox_id(),
                carrier_ceremony_id: *carrier.carrier_ceremony_id(),
                carrier_nonce: *carrier.carrier_nonce(),
                claim_commitment: *carrier.claim_commitment(),
                relay_expires_at: carrier.relay_expires_at(),
                expected_allocator_key: carrier.expected_allocator_key().copied(),
            };
            for field in 0..8 {
                let mut wrong = template.clone();
                match field {
                    0 => wrong.application_context = "https://a.b/other".into(),
                    1 => wrong.relay_origin = "https://other".into(),
                    2 => wrong.mailbox_id[0] ^= 1,
                    3 => wrong.carrier_ceremony_id[0] ^= 1,
                    4 => wrong.carrier_nonce[0] ^= 1,
                    5 => wrong.claim_commitment[0] ^= 1,
                    6 => wrong.relay_expires_at += 1,
                    _ => wrong.expected_allocator_key.as_mut().unwrap()[0] ^= 1,
                }
                let wrong = CredentialV2Carrier::new(wrong).unwrap();
                assert!(
                    Inspection::inspect(
                        sealed,
                        &KEY,
                        &wrong,
                        generation,
                        PD,
                        NOW + 901,
                        mode,
                        Box::new(NoBodies)
                    )
                    .is_err(),
                    "carrier field {field}"
                );
            }
            for length in [0, 1, sealed.len() / 2, sealed.len() - 1] {
                assert!(Inspection::inspect(
                    &sealed[..length],
                    &KEY,
                    &carrier,
                    generation,
                    PD,
                    NOW + 901,
                    mode,
                    Box::new(NoBodies)
                )
                .is_err());
            }
            let mut tampered = sealed.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(Inspection::inspect(
                &tampered,
                &KEY,
                &carrier,
                generation,
                PD,
                NOW + 901,
                mode,
                Box::new(NoBodies)
            )
            .is_err());
        }
        // Inspection did not acknowledge persistence or change the original live
        // attempt: only its exact stored generation can release the cached reply.
        assert!(live.checkpoint_persisted(1).is_err());
        assert_eq!(sent(&live.checkpoint_persisted(2).unwrap()).len(), 2);
    }
}
