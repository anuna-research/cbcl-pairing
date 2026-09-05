//! SPEC-001 TEST-062 Red Gate: authenticated typed credential/v2 display.

use cbcl_pairing::credential_v2::{
    recognise_credential_v2_intent, CredentialV2AccountProvenance, CredentialV2DeviceBinding,
    CredentialV2Display, CredentialV2Error, CredentialV2IntentAuthority, CredentialV2IntentClaims,
    CredentialV2IntentInput, CredentialV2IntentVerifier, CredentialV2Kind, CredentialV2Object,
    CredentialV2OfferParser, CredentialV2TofuState, CredentialV2Transition,
};
use sha2::{Digest, Sha256};

const CEREMONY: [u8; 32] = [0x11; 32];
const PRINCIPAL: [u8; 32] = [0x22; 32];
const SCOPE: [u8; 32] = [0x33; 32];
const DEVICE_KEY: [u8; 32] = [0x44; 32];
const LEGACY_KEY: [u8; 32] = [0x55; 32];
const ROOM_SET: [u8; 32] = [0x66; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const NONCE: [u8; 32] = [0x88; 32];
const OFFER_CORE: [u8; 32] = [0x99; 32];

fn transition() -> CredentialV2Transition {
    CredentialV2Transition::path_a_to_b(
        "@alice",
        LEGACY_KEY,
        vec!["@general".into(), "@ops/alerts!?+*<>=@".into()],
        ROOM_SET,
        SNAPSHOT,
        NONCE,
    )
    .expect("valid transition")
}

fn peer_claims() -> CredentialV2IntentClaims {
    let device_did = format!("did:key:z6Mk{}", "1".repeat(44));
    CredentialV2IntentClaims::new(
        "https://chat.anuna.io/selfsame/v2",
        "https://chat.anuna.io",
        "https://chat.anuna.io:9443",
        CEREMONY,
        CredentialV2AccountProvenance::new(PRINCIPAL, SCOPE),
        vec![
            "https://chat.anuna.io/selfsame/v2#chat-read".into(),
            "https://chat.anuna.io/selfsame/v2#chat-write".into(),
        ],
        CredentialV2DeviceBinding::new(device_did, DEVICE_KEY).expect("valid binding"),
        transition(),
        OFFER_CORE,
    )
    .expect("valid claims")
}

fn intent_digest(offer_core_digest: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"selfsame credential/v2 intent\0");
    hash.update(offer_core_digest);
    hash.finalize().into()
}

fn offer(digest: [u8; 32]) -> CredentialV2Object {
    CredentialV2Object::new(CredentialV2Kind::Offer, intent_digest(digest), vec![0xa1])
        .expect("offer")
}

#[derive(Debug)]
struct Parser {
    calls: usize,
    claims: CredentialV2IntentClaims,
}

impl CredentialV2OfferParser for Parser {
    fn parse_signed_offer(
        &mut self,
        body: &[u8],
    ) -> Result<CredentialV2IntentClaims, CredentialV2Error> {
        assert_eq!(body, [0xa1]);
        self.calls += 1;
        Ok(self.claims.clone())
    }
}

#[derive(Debug, Default)]
struct Verifier {
    calls: usize,
    refuse: bool,
}

impl CredentialV2IntentVerifier for Verifier {
    fn verify(
        &mut self,
        peer: &CredentialV2IntentInput,
        authority: &CredentialV2IntentAuthority,
    ) -> Result<(), CredentialV2Error> {
        self.calls += 1;
        assert_eq!(peer.application_id(), authority.application_id());
        assert_eq!(peer.offer_core_digest(), authority.offer_core_digest());
        if self.refuse {
            Err(CredentialV2Error::Profile)
        } else {
            Ok(())
        }
    }
}

fn authority(claims: CredentialV2IntentClaims) -> CredentialV2IntentAuthority {
    CredentialV2IntentAuthority::new(claims, CredentialV2TofuState::NewPair)
        .expect("valid authority")
}

#[test]
fn test_062_only_an_offer_can_create_peer_input_and_display() {
    let claims = peer_claims();
    let authority = authority(claims.clone());
    let mut parser = Parser { calls: 0, claims };
    let mut verifier = Verifier::default();
    let wrong_kind = CredentialV2Object::new(
        CredentialV2Kind::Payload,
        intent_digest(OFFER_CORE),
        vec![0xa1],
    )
    .expect("payload object");

    assert_eq!(
        recognise_credential_v2_intent(&wrong_kind, &authority, &mut parser, &mut verifier),
        Err(CredentialV2Error::Schema)
    );
    assert_eq!(parser.calls, 0);
    assert_eq!(verifier.calls, 0);
}

#[test]
fn test_062_verdict_only_boundary_copies_only_authority() {
    let claims = peer_claims();
    let authority = authority(claims.clone());
    let mut parser = Parser {
        calls: 0,
        claims: claims.clone(),
    };
    let mut refusing = Verifier {
        calls: 0,
        refuse: true,
    };

    assert_eq!(
        recognise_credential_v2_intent(&offer(OFFER_CORE), &authority, &mut parser, &mut refusing,),
        Err(CredentialV2Error::Profile)
    );
    assert_eq!(parser.calls, 1);
    assert_eq!(refusing.calls, 1);

    let mut parser = Parser { calls: 0, claims };
    let mut accepting = Verifier::default();
    let display =
        recognise_credential_v2_intent(&offer(OFFER_CORE), &authority, &mut parser, &mut accepting)
            .expect("authenticated display");

    assert_display_matches_authority(&display, &authority);
    assert_eq!(parser.calls, 1);
    assert_eq!(accepting.calls, 1);
}

#[test]
fn test_062_every_overlapping_peer_mismatch_refuses_before_verifier() {
    let base = peer_claims();
    let authority = authority(base.clone());
    let variants = [
        base.clone()
            .with_application_id("https://chat.anuna.io/evil/v2"),
        base.clone().with_https_origin("https://evil.example"),
        base.clone().with_relay_origin("https://evil.example:9443"),
        base.clone().with_carrier_ceremony_id([0xa1; 32]),
        base.clone()
            .with_account_provenance(CredentialV2AccountProvenance::new([0xa2; 32], SCOPE)),
        base.clone()
            .with_permissions(vec!["https://evil.example/selfsame/v2#chat-admin".into()]),
        base.clone().with_device_binding(
            CredentialV2DeviceBinding::new(format!("did:key:z6Mk{}", "2".repeat(44)), [0xa3; 32])
                .unwrap(),
        ),
        base.clone()
            .with_transition(CredentialV2Transition::NoTransition),
        base.clone().with_offer_core_digest([0xa4; 32]),
    ];

    for claims in variants {
        let digest = *claims.offer_core_digest();
        let mut parser = Parser { calls: 0, claims };
        let mut verifier = Verifier::default();
        assert_eq!(
            recognise_credential_v2_intent(&offer(digest), &authority, &mut parser, &mut verifier,),
            Err(CredentialV2Error::Profile)
        );
        assert_eq!(parser.calls, 1);
        assert_eq!(verifier.calls, 0);
    }

    let mut parser = Parser {
        calls: 0,
        claims: base,
    };
    let mut verifier = Verifier::default();
    let wrong_intent = CredentialV2Object::new(CredentialV2Kind::Offer, [0xfe; 32], vec![0xa1])
        .expect("offer with wrong intent");
    assert_eq!(
        recognise_credential_v2_intent(&wrong_intent, &authority, &mut parser, &mut verifier,),
        Err(CredentialV2Error::Profile)
    );
    assert_eq!(verifier.calls, 0);
}

#[test]
fn test_062_transition_room_grammar_and_constructive_maximum_are_exact() {
    let branch_room = "@Az09_-.//!?+*<>=@";
    assert!(CredentialV2Transition::path_a_to_b(
        "@a0_-",
        LEGACY_KEY,
        vec![branch_room.into()],
        ROOM_SET,
        SNAPSHOT,
        NONCE,
    )
    .is_ok());

    for invalid in [
        "general",
        "@",
        "@room space",
        "@room\\escape",
        "@room\"quote",
    ] {
        assert!(CredentialV2Transition::path_a_to_b(
            "@alice",
            LEGACY_KEY,
            vec![invalid.into()],
            ROOM_SET,
            SNAPSHOT,
            NONCE,
        )
        .is_err());
    }

    let rooms: Vec<String> = (0_u16..256)
        .map(|number| format!("@{number:04x}{}", "a".repeat(124)))
        .collect();
    assert_eq!(serde_json::to_vec(&rooms).unwrap().len(), 33_793);
    let maximum = CredentialV2Transition::path_a_to_b(
        "@abcdefghijklmnopqrstuvwxyz012345",
        LEGACY_KEY,
        rooms.clone(),
        ROOM_SET,
        SNAPSHOT,
        NONCE,
    )
    .expect("constructible maximum transition");
    assert_eq!(maximum.as_path_a_to_b().unwrap().migration_rooms(), rooms);

    let mut duplicate = rooms.clone();
    duplicate[255] = duplicate[254].clone();
    assert!(CredentialV2Transition::path_a_to_b(
        "@alice", LEGACY_KEY, duplicate, ROOM_SET, SNAPSHOT, NONCE,
    )
    .is_err());
    let mut reversed = rooms;
    reversed.reverse();
    assert!(CredentialV2Transition::path_a_to_b(
        "@alice", LEGACY_KEY, reversed, ROOM_SET, SNAPSHOT, NONCE,
    )
    .is_err());
}

fn assert_display_matches_authority(
    display: &CredentialV2Display,
    authority: &CredentialV2IntentAuthority,
) {
    assert_eq!(display.application_id(), authority.application_id());
    assert_eq!(display.https_origin(), authority.https_origin());
    assert_eq!(display.relay_origin(), authority.relay_origin());
    assert_eq!(
        display.carrier_ceremony_id(),
        authority.carrier_ceremony_id()
    );
    assert_eq!(display.account_provenance(), authority.account_provenance());
    assert_eq!(display.permissions(), authority.permissions());
    assert_eq!(display.device_binding(), authority.device_binding());
    assert_eq!(display.tofu_state(), authority.tofu_state());
    assert_eq!(display.transition(), authority.transition());
    assert_eq!(display.offer_core_digest(), authority.offer_core_digest());
}

// SPEC-079 CON-001 / SPEC-001 CON-029: provenance is local consumer authority.
#[test]
fn ceremony_contact_is_truthful_and_cannot_be_supplied_by_peer_claims() {
    let object = offer(OFFER_CORE);
    for provenance in [
        CredentialV2TofuState::CeremonyGesture,
        CredentialV2TofuState::NewPair,
        CredentialV2TofuState::TrustedPair,
    ] {
        let claims = peer_claims();
        let authority = CredentialV2IntentAuthority::new(claims.clone(), provenance).unwrap();
        let mut parser = Parser { calls: 0, claims };
        let mut verifier = Verifier::default();
        let display =
            recognise_credential_v2_intent(&object, &authority, &mut parser, &mut verifier)
                .unwrap();
        assert_eq!(display.tofu_state(), provenance);
        assert_eq!(authority.tofu_state(), provenance);
        assert_eq!(verifier.calls, 1);
        assert_eq!(display.application_id(), authority.application_id());
        assert_eq!(
            display.carrier_ceremony_id(),
            authority.carrier_ceremony_id()
        );
        // Same peer bytes and claims in all three cases; verifier refusal still blocks display.
        verifier.refuse = true;
        assert_eq!(
            recognise_credential_v2_intent(&object, &authority, &mut parser, &mut verifier),
            Err(CredentialV2Error::Profile)
        );
    }
}
