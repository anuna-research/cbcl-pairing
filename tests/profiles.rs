//! Conformance cases for SPEC-072 application profiles.

use cbcl_pairing::{
    profile::{
        encode_agent_word_indices, AgentGrant, AgentIntentClaims, AgentProfile, AgentWordPair,
        ApplicationProfile, CredentialGrant, CredentialIntentClaims, CredentialProfile,
        GrantVerifier, LocatorKind, ProfileError, RecognisedPayload, SyntheticGrant,
        SyntheticIntentClaims, SyntheticProfile, AGENT_ACTION, AGENT_APPLICATION, AGENT_PAYLOAD,
        CREDENTIAL_ACTION, CREDENTIAL_APPLICATION, CREDENTIAL_PAYLOAD, SYNTHETIC_ACTION,
        SYNTHETIC_APPLICATION, SYNTHETIC_PAYLOAD,
    },
    wire::{ApplicationPayload, Invitation, Locator, PairingIntent},
};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug)]
struct RecordingVerifier {
    calls: Arc<AtomicUsize>,
    allow: bool,
}

#[test]
fn test_006_agent_carrier_derives_two_independent_bip39_words_from_22_csprng_bits() {
    let zero = AgentWordPair::from_csprng_octets([0, 0, 0]);
    assert_eq!(zero.indices(), [0, 0]);
    assert_eq!(zero.words(), ["abandon", "abandon"]);
    assert_eq!(zero.secret(), [0, 0, 0, 0]);

    let maximum = AgentWordPair::from_csprng_octets([0xff, 0xff, 0xff]);
    assert_eq!(maximum.indices(), [2047, 2047]);
    assert_eq!(maximum.words(), ["zoo", "zoo"]);
    assert_eq!(maximum.secret(), [0x07, 0xff, 0x07, 0xff]);

    let generated = AgentWordPair::from_csprng_octets([0x12, 0x34, 0x56]);
    let [first, second] = generated.words();
    assert_eq!(AgentWordPair::recognise(first, second), Ok(generated));
    assert_eq!(
        AgentWordPair::recognise("not-a-bip39-word", second),
        Err(ProfileError::InvalidInvitation)
    );
    assert_eq!(
        AgentWordPair::recognise(&first.to_ascii_uppercase(), second),
        Err(ProfileError::InvalidInvitation),
        "carrier recognition performs no case folding"
    );
}

impl GrantVerifier for RecordingVerifier {
    fn verify(&mut self, _payload: &RecognisedPayload) -> Result<(), ProfileError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.allow {
            Ok(())
        } else {
            Err(ProfileError::Unauthorized)
        }
    }
}

fn verifier(allow: bool) -> (Box<dyn GrantVerifier>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Box::new(RecordingVerifier {
            calls: Arc::clone(&calls),
            allow,
        }),
        calls,
    )
}

fn invitation(application: &str, locator: Locator, secret: Vec<u8>) -> Invitation {
    Invitation {
        application: application.into(),
        relay_origin: "https://relay.example".into(),
        locator,
        secret,
        expected_allocator_key: None,
        expected_claimant_key: None,
    }
}

fn intent(application: &str, action: &str, claims: (Vec<u8>, Vec<u8>)) -> PairingIntent {
    PairingIntent {
        application: application.into(),
        action: action.into(),
        allocator_claim: claims.0,
        claimant_claim: claims.1,
        authority_summary: "Explicit approval is required".into(),
        intent_nonce: [0x44; 32],
    }
}

#[test]
fn test_010_profiles_are_endpoint_local_and_describe_their_carriers() {
    let (agent_verifier, _) = verifier(true);
    let agent = AgentProfile::new(agent_verifier);
    let (credential_verifier, _) = verifier(true);
    let credential = CredentialProfile::new(credential_verifier);
    let synthetic = SyntheticProfile::new(true);

    assert_eq!(agent.descriptor().application, AGENT_APPLICATION);
    assert_eq!(agent.descriptor().carrier.locator, LocatorKind::Nameplate);
    assert_eq!(agent.descriptor().carrier.minimum_entropy_bits, 22);
    assert_eq!(credential.descriptor().application, CREDENTIAL_APPLICATION);
    assert_eq!(credential.descriptor().carrier.locator, LocatorKind::Direct);
    assert_eq!(credential.descriptor().carrier.minimum_entropy_bits, 128);
    assert_eq!(synthetic.descriptor().application, SYNTHETIC_APPLICATION);

    let words = encode_agent_word_indices(7, 2047).expect("two indices");
    agent
        .recognise_invitation(&invitation(
            AGENT_APPLICATION,
            Locator::Nameplate(123),
            words.to_vec(),
        ))
        .expect("agent carrier");
    credential
        .recognise_invitation(&invitation(
            CREDENTIAL_APPLICATION,
            Locator::Direct([0x11; 32]),
            vec![0x22; 16],
        ))
        .expect("credential carrier");
    synthetic
        .recognise_invitation(&invitation(
            SYNTHETIC_APPLICATION,
            Locator::Direct([0x33; 32]),
            vec![0x44; 16],
        ))
        .expect("synthetic carrier");

    let agent_claims = AgentIntentClaims {
        channel: "stable".into(),
        claimed_principal: "alice@example.test".into(),
        agent_handle: "agent-7".into(),
        requested_grant: "chat".into(),
    }
    .encode()
    .expect("agent claims");
    assert!(agent
        .recognise_intent(&intent(AGENT_APPLICATION, AGENT_ACTION, agent_claims))
        .is_ok());

    let credential_claims = CredentialIntentClaims {
        application_id: "com.example.wallet".into(),
        origin: "https://wallet.example".into(),
        scope: "account:read".into(),
        recipient: "new phone".into(),
    }
    .encode()
    .expect("credential claims");
    assert!(credential
        .recognise_intent(&intent(
            CREDENTIAL_APPLICATION,
            CREDENTIAL_ACTION,
            credential_claims,
        ))
        .is_ok());

    let synthetic_claims = SyntheticIntentClaims {
        subject: "subject-1".into(),
        audience: "audience-2".into(),
    }
    .encode()
    .expect("synthetic claims");
    assert!(synthetic
        .recognise_intent(&intent(
            SYNTHETIC_APPLICATION,
            SYNTHETIC_ACTION,
            synthetic_claims,
        ))
        .is_ok());
}

#[test]
fn test_010_synthetic_profile_leaves_relay_assets_byte_identical() {
    for (bytes, expected) in [
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/bin/cbcl-pairing-relay.rs"
            ))
            .as_slice(),
            "19daf1d84007e02606070539494e9a75984baaacfe598646906b5468d68b2e1d",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/bin/cbcl-pairing-relay-ws.rs"
            ))
            .as_slice(),
            "58d113d4811c710c219d939e8f6cdcb1ab9ef72d98f2ee4fb0e80213182736bf",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/schemas/pairing-v1.cddl"
            ))
            .as_slice(),
            "c8f7e57a1a944dd999ebeeb20260368d3315ade26748fbab8361de2643240fc9",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mailbox.rs")).as_slice(),
            "b385a9edb0ec1a34f1930daf94ffec977be78feb61887c31856e22d18c05da07",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage.rs")).as_slice(),
            "0b9725180d06bdac907bbaeb1fafab06daa1ce45bbc409ada3cefc51a51fa1d5",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/relay.rs")).as_slice(),
            "2acefa153b79a983bcacbdc6992fa854d162833e14e7809606d0aeba68d0d972",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limiter.rs")).as_slice(),
            "ace64e6c89d745b305af0c5dca42c5e90ab2643ce0ae0f009d66c41ce68e59ca",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/observability.rs")).as_slice(),
            "5c357c35c3a781b39ed1848fa9c6ab34dd3eb2c282a3114be9d9e7825e4b0ed8",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).as_slice(),
            "48b35c9ce45ac1a0f1baf168f428510901f031675f077f862d68a97694e696e5",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/.forgejo/workflows/ci.yml"
            ))
            .as_slice(),
            "ff2e799e83cf488a1dd5f355713638c195fa79790883b74c5a679e4666b1b6ac",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected);
    }
}

#[test]
fn profile_payloads_are_canonical_bound_and_verifier_owned() {
    let claims = AgentIntentClaims {
        channel: "stable".into(),
        claimed_principal: "alice@example.test".into(),
        agent_handle: "agent-7".into(),
        requested_grant: "chat".into(),
    };
    let (verifier, calls) = verifier(true);
    let mut profile = AgentProfile::new(verifier);
    let (_, binding) = profile
        .recognise_intent(&intent(
            AGENT_APPLICATION,
            AGENT_ACTION,
            claims.clone().encode().expect("claims"),
        ))
        .expect("intent")
        .into_parts();
    let payload = ApplicationPayload {
        intent_digest: [0x55; 32],
        payload_type: AGENT_PAYLOAD.into(),
        body: AgentGrant {
            claimed_principal: claims.claimed_principal,
            agent_handle: claims.agent_handle,
            requested_grant: claims.requested_grant,
            grant: b"signed SPEC-061 grant".to_vec(),
        }
        .encode()
        .expect("grant"),
    };
    let recognised = profile
        .recognise_payload(&binding, &payload)
        .expect("bound payload");
    profile
        .authorize_payload(recognised)
        .expect("authoritative verifier");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut malformed = payload.clone();
    malformed.body.push(0);
    assert_eq!(
        profile.recognise_payload(&binding, &malformed),
        Err(ProfileError::InvalidPayload)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn credential_and_synthetic_payloads_bind_every_profile_field() {
    let credential_claims = CredentialIntentClaims {
        application_id: "com.example.wallet".into(),
        origin: "https://wallet.example".into(),
        scope: "account:read".into(),
        recipient: "new phone".into(),
    };
    let (credential_verifier, _) = verifier(true);
    let credential = CredentialProfile::new(credential_verifier);
    let (_, credential_binding) = credential
        .recognise_intent(&intent(
            CREDENTIAL_APPLICATION,
            CREDENTIAL_ACTION,
            credential_claims.clone().encode().expect("claims"),
        ))
        .expect("intent")
        .into_parts();
    let credential_payload = ApplicationPayload {
        intent_digest: [0x66; 32],
        payload_type: CREDENTIAL_PAYLOAD.into(),
        body: CredentialGrant {
            application_id: credential_claims.application_id,
            origin: credential_claims.origin,
            scope: credential_claims.scope,
            recipient: credential_claims.recipient,
            credential: b"account-scoped credential".to_vec(),
        }
        .encode()
        .expect("credential"),
    };
    assert!(credential
        .recognise_payload(&credential_binding, &credential_payload)
        .is_ok());

    let synthetic_claims = SyntheticIntentClaims {
        subject: "subject-1".into(),
        audience: "audience-2".into(),
    };
    let synthetic = SyntheticProfile::new(true);
    let (_, synthetic_binding) = synthetic
        .recognise_intent(&intent(
            SYNTHETIC_APPLICATION,
            SYNTHETIC_ACTION,
            synthetic_claims.clone().encode().expect("claims"),
        ))
        .expect("intent")
        .into_parts();
    let mut wrong = synthetic_claims;
    wrong.audience = "other-audience".into();
    let payload = ApplicationPayload {
        intent_digest: [0x77; 32],
        payload_type: SYNTHETIC_PAYLOAD.into(),
        body: SyntheticGrant {
            subject: wrong.subject,
            audience: wrong.audience,
            grant: b"authorized".to_vec(),
        }
        .encode()
        .expect("synthetic payload"),
    };
    assert_eq!(
        synthetic.recognise_payload(&synthetic_binding, &payload),
        Err(ProfileError::InvalidPayload)
    );
}
