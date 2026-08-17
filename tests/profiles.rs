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
            "c711f24f19f2e76da03493e478274cfdc50a9431c53520056e0fb42ff8951562",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/bin/cbcl-pairing-relay-ws.rs"
            ))
            .as_slice(),
            "9fbcf0fe4d2281f4a7c147080996045033204a74fe5b5e79bc9a6f7e69416ed0",
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
            "5df5fdca0c9105140e5ab20a7155b3db56030738b1b0a3d60a5ba77d8ee969f6",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/storage.rs")).as_slice(),
            "0b9725180d06bdac907bbaeb1fafab06daa1ce45bbc409ada3cefc51a51fa1d5",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/relay.rs")).as_slice(),
            "fd2956de38791f96660615feccba0d0287da1eebf3bbda1a8c74a4600d3af834",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limiter.rs")).as_slice(),
            "0ababe90ba3040f6fd66dbefc9041d23e040e872b1f007e60d4aa3ba596b3d47",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/observability.rs")).as_slice(),
            "892fd61c0a8d1cc3cbf24f0633f5a8dcbb32ea7f82a5363cd8daf1fb9b8bd177",
        ),
        (
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).as_slice(),
            "b71ff778cb624ba855c8125d38939283fb55b55e1af50375f02ef582d729d84a",
        ),
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/.forgejo/workflows/ci.yml"
            ))
            .as_slice(),
            "857475d0f11d7c993d055a4812d11b142602ba6335b045271194b4230a0c0d36",
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

fn agent_claims(channel: &str) -> AgentIntentClaims {
    AgentIntentClaims {
        channel: channel.to_owned(),
        claimed_principal: "principal".to_owned(),
        agent_handle: "handle".to_owned(),
        requested_grant: "grant".to_owned(),
    }
}

fn credential_claims(origin: &str) -> CredentialIntentClaims {
    CredentialIntentClaims {
        application_id: "application".to_owned(),
        origin: origin.to_owned(),
        scope: "scope".to_owned(),
        recipient: "recipient".to_owned(),
    }
}

#[test]
fn bounded_claim_text_holds_at_its_exact_limit_and_refuses_the_edges() {
    // The channel field is bounded at 64 characters. Sitting exactly on the
    // limit is what distinguishes `>` from `>=`; only testing well inside and
    // well outside leaves the boundary itself unproven.
    agent_claims(&"c".repeat(64))
        .encode()
        .expect("a channel of exactly the maximum length is accepted");

    for (why, channel) in [
        ("one character past the maximum", "c".repeat(65)),
        ("an empty value", String::new()),
        ("an embedded control character", "chan\u{7}nel".to_owned()),
        ("an embedded newline", "chan\nnel".to_owned()),
    ] {
        assert_eq!(
            agent_claims(&channel).encode().unwrap_err(),
            ProfileError::InvalidClaim,
            "a channel with {why} must be refused"
        );
    }

    // The same bound applies to the fields validated together with it.
    for (why, claims) in [
        (
            "an over-long principal",
            AgentIntentClaims {
                claimed_principal: "p".repeat(256),
                ..agent_claims("channel")
            },
        ),
        (
            "an over-long handle",
            AgentIntentClaims {
                agent_handle: "h".repeat(129),
                ..agent_claims("channel")
            },
        ),
        (
            "an over-long requested grant",
            AgentIntentClaims {
                requested_grant: "g".repeat(129),
                ..agent_claims("channel")
            },
        ),
    ] {
        assert_eq!(
            claims.encode().unwrap_err(),
            ProfileError::InvalidClaim,
            "claims with {why} must be refused"
        );
    }
}

#[test]
fn credential_origins_must_be_canonical_https_authorities() {
    credential_claims("https://example.com")
        .encode()
        .expect("a canonical https origin is accepted");
    credential_claims("https://example.com:8443")
        .encode()
        .expect("an explicit port stays canonical");

    for (why, origin) in [
        ("a plaintext scheme", "http://example.com"),
        ("a non-web scheme", "ftp://example.com"),
        ("embedded credentials", "https://user@example.com"),
        ("an embedded password", "https://user:secret@example.com"),
        ("a query string", "https://example.com/?scope=all"),
        ("a fragment", "https://example.com/#section"),
        ("a path segment", "https://example.com/callback"),
        ("a trailing slash", "https://example.com/"),
        ("no host at all", "https://"),
        ("an unparseable value", "not a url"),
    ] {
        assert_eq!(
            credential_claims(origin).encode().unwrap_err(),
            ProfileError::InvalidClaim,
            "an origin with {why} must be refused"
        );
    }
}

#[test]
fn grant_payloads_hold_at_both_ends_of_their_size_bound() {
    let grant = |bytes: Vec<u8>| AgentGrant {
        claimed_principal: "principal".to_owned(),
        agent_handle: "handle".to_owned(),
        requested_grant: "grant".to_owned(),
        grant: bytes,
    };

    grant(vec![0x5a])
        .encode()
        .expect("a single grant octet meets the minimum");
    grant(vec![0x5a; 63_000])
        .encode()
        .expect("a grant of exactly the maximum size is accepted");

    assert_eq!(
        grant(Vec::new()).encode().unwrap_err(),
        ProfileError::InvalidPayload,
        "an empty grant is below the minimum"
    );
    assert_eq!(
        grant(vec![0x5a; 63_001]).encode().unwrap_err(),
        ProfileError::InvalidPayload,
        "one octet past the maximum must be refused"
    );
}

#[test]
fn synthetic_claims_are_bounded_on_both_fields() {
    let claims = |subject: String, audience: String| SyntheticIntentClaims { subject, audience };

    claims("s".repeat(128), "a".repeat(128))
        .encode()
        .expect("fields of exactly the maximum length are accepted");

    for (why, subject, audience) in [
        (
            "an over-long subject",
            "s".repeat(129),
            "audience".to_owned(),
        ),
        (
            "an over-long audience",
            "subject".to_owned(),
            "a".repeat(129),
        ),
        ("an empty subject", String::new(), "audience".to_owned()),
        ("an empty audience", "subject".to_owned(), String::new()),
    ] {
        assert_eq!(
            claims(subject, audience).encode().unwrap_err(),
            ProfileError::InvalidClaim,
            "synthetic claims with {why} must be refused"
        );
    }
}
