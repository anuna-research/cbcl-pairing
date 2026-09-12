//! SPEC-054 CON-012 profile recognition. No hub admission or custody claim.
use cbcl_pairing::{
    profile::{archive::*, ApplicationProfile, ProfileError},
    wire::{ApplicationPayload, Invitation, Locator, PairingIntent},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug)]
struct Verifier {
    calls: Arc<AtomicUsize>,
    allow: bool,
}
impl EnrollmentVerifier for Verifier {
    fn verify(&mut self, enrollment: &Enrollment) -> Result<(), ProfileError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(enrollment.manifest, b"synthetic signed manifest");
        if self.allow {
            Ok(())
        } else {
            Err(ProfileError::Unauthorized)
        }
    }
}
fn claims() -> Claims {
    Claims {
        owner: "did:example:owner".into(),
        chain: [1; 32],
        previous: [2; 32],
        allocator: [3; 32],
        recipient: [4; 32],
        hpke: [5; 32],
    }
}
fn profile(allow: bool) -> (ArchiveProfile, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        ArchiveProfile::new(
            [[7; 32], [8; 32]],
            [[3; 32], [4; 32]],
            Box::new(Verifier {
                calls: calls.clone(),
                allow,
            }),
        ),
        calls,
    )
}
fn intent() -> PairingIntent {
    let (a, c) = claims().encode().unwrap();
    PairingIntent {
        application: APPLICATION.into(),
        action: ACTION.into(),
        allocator_claim: a,
        claimant_claim: c,
        authority_summary: SUMMARY.into(),
        intent_nonce: [9; 32],
    }
}
fn payload(c: Claims) -> ApplicationPayload {
    ApplicationPayload {
        intent_digest: [6; 32],
        payload_type: PAYLOAD.into(),
        body: Enrollment {
            claims: c,
            manifest: b"synthetic signed manifest".to_vec(),
        }
        .encode()
        .unwrap(),
    }
}

#[test]
fn bound_descriptor_requires_archive_verifier() {
    for allow in [true, false] {
        let (mut profile, calls) = profile(allow);
        let (display, binding) = profile.recognise_intent(&intent()).unwrap().into_parts();
        assert_eq!(display.authority_summary(), SUMMARY);
        let recognized = profile
            .recognise_payload(&binding, &payload(claims()))
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(profile.authorize_payload(recognized).is_ok(), allow);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn every_approved_claim_is_bound_before_verifier() {
    let (mut profile, calls) = profile(true);
    let (_, binding) = profile.recognise_intent(&intent()).unwrap().into_parts();
    for i in 0..6 {
        let mut c = claims();
        match i {
            0 => c.owner.push('x'),
            1 => c.chain[0] ^= 1,
            2 => c.previous[0] ^= 1,
            3 => c.allocator[0] ^= 1,
            4 => c.recipient[0] ^= 1,
            _ => c.hpke[0] ^= 1,
        };
        assert!(profile.recognise_payload(&binding, &payload(c)).is_err());
    }
    let mut wrong = payload(claims());
    wrong.payload_type = "anuna.io/account-credential/v1".into();
    assert!(profile.recognise_payload(&binding, &wrong).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[test]
fn invitation_and_intent_domains_are_distinct() {
    let (mut profile, _) = profile(true);
    let invitation = Invitation {
        application: APPLICATION.into(),
        relay_origin: "https://relay.example".into(),
        locator: Locator::Direct([1; 32]),
        secret: vec![2; 16],
        expected_allocator_key: Some([7; 32]),
        expected_claimant_key: Some([8; 32]),
    };
    profile.recognise_invitation(&invitation).unwrap();
    for i in 0..5 {
        let mut bad = invitation.clone();
        match i {
            0 => bad.application = "anuna.io/credential/v1".into(),
            1 => bad.secret.pop().map(|_| ()).unwrap(),
            2 => bad.locator = Locator::Nameplate(12345),
            3 => bad.expected_allocator_key = Some([3; 32]),
            _ => bad.expected_claimant_key = None,
        };
        assert!(profile.recognise_invitation(&bad).is_err());
    }
    for i in 0..4 {
        let mut bad = intent();
        match i {
            0 => bad.action = "transfer-credential".into(),
            1 => bad.application = "anuna.io/credential/v1".into(),
            2 => bad.authority_summary = "Only read public metadata".into(),
            _ => {
                let mut c = claims();
                c.recipient = [99; 32];
                bad.claimant_claim = c.encode().unwrap().1;
            }
        };
        assert!(profile.recognise_intent(&bad).is_err());
    }
}
#[test]
fn closed_nested_grammar_and_bounds() {
    let (a, c) = claims().encode().unwrap();
    assert_eq!(Claims::decode(&a, &c).unwrap(), claims());
    for n in 0..a.len() {
        assert!(Claims::decode(&a[..n], &c).is_err());
    }
    let mut trailing = a.clone();
    trailing.push(0);
    assert!(Claims::decode(&trailing, &c).is_err());
    let mut value: ciborium::Value = ciborium::from_reader(a.as_slice()).unwrap();
    if let ciborium::Value::Map(fields) = &mut value {
        fields.push(fields[0].clone());
    }
    let mut duplicate = Vec::new();
    ciborium::into_writer(&value, &mut duplicate).unwrap();
    assert!(Claims::decode(&duplicate, &c).is_err());
    for owner in ["".to_string(), "x".repeat(257), "bad\nowner".into()] {
        let mut bad = claims();
        bad.owner = owner;
        assert!(bad.encode().is_err());
    }
    let mut bad = claims();
    bad.recipient = bad.allocator;
    assert!(bad.encode().is_err());
    for size in [0, 16385] {
        assert!(Enrollment {
            claims: claims(),
            manifest: vec![1; size]
        }
        .encode()
        .is_err());
    }
    let max = Enrollment {
        claims: claims(),
        manifest: vec![1; 16384],
    };
    assert_eq!(Enrollment::decode(&max.encode().unwrap()).unwrap(), max);
    let mut descriptor = max.encode().unwrap();
    descriptor.push(0);
    assert!(Enrollment::decode(&descriptor).is_err());
}
