//! Conformance cases for SPEC-072 application profiles.

use cbcl_pairing::{
    profile::{
        encode_agent_word_indices, AgentGrant, AgentIntentClaims, AgentProfile, ApplicationProfile,
        CredentialGrant, CredentialIntentClaims, CredentialProfile, GrantVerifier, LocatorKind,
        ProfileError, RecognisedPayload, SyntheticGrant, SyntheticIntentClaims, SyntheticProfile,
        AGENT_ACTION, AGENT_APPLICATION, AGENT_PAYLOAD, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION,
        CREDENTIAL_PAYLOAD, SYNTHETIC_ACTION, SYNTHETIC_APPLICATION, SYNTHETIC_PAYLOAD,
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
            "f9edfbff5440fc937350ae5b52559017105c6c78c4695764692b424414742d7b",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/schemas/pairing-v1.cddl"
            ))
            .as_slice(),
            "841ae4106becd28718028cab50058877d0ab30bd38a7d39c2b224e4a1e63a103",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mailbox.rs")).as_slice(),
            "19541cfaee3b158492ab997d3bbbb058fcf98b06d34b4fc60009a09bb751abe5",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limiter.rs")).as_slice(),
            "871cba629c34269e81ad37ef0acf8769ec09ca5cbd91efac81b8ef990e130f82",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/observability.rs")).as_slice(),
            "5c357c35c3a781b39ed1848fa9c6ab34dd3eb2c282a3114be9d9e7825e4b0ed8",
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
