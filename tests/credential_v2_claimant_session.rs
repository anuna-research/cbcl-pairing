//! SPEC-001 CON-030 claimant bootstrap stays restart-abandonable.

use cbcl_pairing::{
    cpace,
    credential_v2::{
        decode_frame, encode_frame, CredentialV2Advance, CredentialV2BodyVerifier,
        CredentialV2Carrier, CredentialV2CarrierInput, CredentialV2ClaimantEffect,
        CredentialV2ClaimantOfferVerifier, CredentialV2ClaimantSession,
        CredentialV2ClaimantSessionInput, CredentialV2Context, CredentialV2Endpoint,
        CredentialV2Error, CredentialV2Frame, CredentialV2LogicalBody, CredentialV2Object,
        CredentialV2Presence, CredentialV2PresenceCode, PendingCredentialV2Channel,
    },
    wire::{
        claim_commitment, decode_client_message, encode_server_message, ClaimToken, ClientMessage,
        ServerMessage, Side,
    },
};

const NOW: u64 = 1_800_000_000;
const EXPIRY: u64 = NOW + 900;
const MAILBOX: [u8; 32] = [0x61; 32];
const CPACE_SECRET: [u8; 16] = [0x62; 16];
const CLAIM_TOKEN: [u8; 16] = [0x63; 16];
const PROFILE_DIGEST: [u8; 32] = [0x64; 32];
const MEMBERSHIP: [u8; 32] = [0x65; 32];

#[derive(Debug)]
struct AcceptBodies;

impl CredentialV2BodyVerifier for AcceptBodies {
    fn verify(&mut self, _: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Ok(())
    }
}

#[derive(Debug)]
struct UnusedOfferVerifier;

impl CredentialV2ClaimantOfferVerifier for UnusedOfferVerifier {
    fn verify_offer(
        &mut self,
        _: &mut CredentialV2Endpoint,
        _: &CredentialV2Object,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        panic!("bootstrap must not attempt to display an offer")
    }
}

fn carrier() -> CredentialV2Carrier {
    CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: MAILBOX,
        carrier_ceremony_id: [0x66; 32],
        carrier_nonce: [0x67; 32],
        claim_commitment: claim_commitment(MAILBOX, &ClaimToken::new(CLAIM_TOKEN)),
        relay_expires_at: EXPIRY,
        expected_allocator_key: Some([0x68; 32]),
    })
    .unwrap()
}

fn server(message: ServerMessage) -> Vec<u8> {
    encode_server_message(&message).unwrap()
}

fn sent(effects: &[CredentialV2ClaimantEffect]) -> Vec<ClientMessage> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            CredentialV2ClaimantEffect::Send(bytes) => Some(decode_client_message(bytes).unwrap()),
            _ => None,
        })
        .collect()
}

#[test]
fn claimant_completes_claim_cpace_and_finished_without_a_preapproval_checkpoint() {
    let recognised_carrier = carrier();
    let mut claimant = CredentialV2ClaimantSession::new(
        CredentialV2ClaimantSessionInput {
            carrier: recognised_carrier.clone(),
            presence_code: CredentialV2PresenceCode::new(CPACE_SECRET, CLAIM_TOKEN),
            cpace_scalar: [0x69; 32],
            profile_digest: PROFILE_DIGEST,
        },
        Box::new(AcceptBodies),
        Box::new(UnusedOfferVerifier),
    )
    .unwrap();
    assert_eq!(
        decode_client_message(&claimant.start().unwrap()).unwrap(),
        ClientMessage::Bind,
    );

    let claim = claimant
        .receive(&server(ServerMessage::Welcome), NOW)
        .unwrap();
    assert_eq!(
        sent(&claim),
        vec![ClientMessage::ClaimV2 {
            mailbox_id: MAILBOX,
            claim_token: ClaimToken::new(CLAIM_TOKEN),
        }],
    );

    let claimant_share_effects = claimant
        .receive(
            &server(ServerMessage::ClaimedV2 {
                mailbox_id: MAILBOX,
                membership_token: MEMBERSHIP,
                expires_at: EXPIRY,
            }),
            NOW,
        )
        .unwrap();
    let claimant_share_commands = sent(&claimant_share_effects);
    let [ClientMessage::Put {
        seq: 0,
        body: claimant_share,
    }] = claimant_share_commands.as_slice()
    else {
        panic!("claimant CPace share must be exact relay sequence zero")
    };
    let claimant_share = decode_frame(claimant_share).unwrap();

    let context = CredentialV2Context::derive(&recognised_carrier, PROFILE_DIGEST).unwrap();
    let allocator_presence = CredentialV2Presence::new(CPACE_SECRET, CLAIM_TOKEN);
    let (allocator_state, allocator_message) = context
        .start_cpace(Side::Allocator, &allocator_presence, [0x73; 32])
        .unwrap();
    let allocator_share = CredentialV2Frame::cpace(&allocator_message).unwrap();

    assert!(claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 0 }), NOW)
        .unwrap()
        .is_empty());

    let finished_effects = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 0,
                body: encode_frame(&allocator_share).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    let commands = sent(&finished_effects);
    assert_eq!(commands[0], ClientMessage::Ack { peer_seq: 0 });
    let ClientMessage::Put {
        seq: 1,
        body: claimant_finished,
    } = &commands[1]
    else {
        panic!("claimant Finished must be exact relay sequence one")
    };
    let claimant_finished = decode_frame(claimant_finished).unwrap();

    let allocator_isk = cpace::finish(
        allocator_state,
        claimant_share
            .cpace_message()
            .expect("claimant CPace share"),
    )
    .unwrap();
    let allocator_pending = PendingCredentialV2Channel::new(
        Side::Allocator,
        allocator_isk,
        context.public_context(),
        &encode_frame(&allocator_share).unwrap(),
        &encode_frame(&claimant_share).unwrap(),
    )
    .unwrap();
    let allocator_finished = allocator_pending.local_finished_frame();
    assert!(allocator_pending.confirm(&claimant_finished).is_ok());

    assert!(claimant
        .receive(&server(ServerMessage::Acknowledged { seq: 1 }), NOW)
        .unwrap()
        .is_empty());
    let established = claimant
        .receive(
            &server(ServerMessage::Frame {
                peer_seq: 1,
                body: encode_frame(&allocator_finished).unwrap(),
            }),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        established.as_slice(),
        [CredentialV2ClaimantEffect::Send(_), CredentialV2ClaimantEffect::Established {
            transcript_hash
        }] if transcript_hash.len() == 64
    ));
    assert_eq!(sent(&established), vec![ClientMessage::Ack { peer_seq: 1 }]);

    claimant.authorise_authenticated_profile().unwrap();
    assert_eq!(
        claimant.authorise_authenticated_profile(),
        Err(CredentialV2Error::Phase),
    );
}
