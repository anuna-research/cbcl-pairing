//! Red Gate and conformance cases for SPEC-072 application profiles.

use cbcl_pairing::{
    profile::{
        AgentProfile, ApplicationProfile, CredentialProfile, LocatorKind, SyntheticProfile,
        AGENT_APPLICATION, CREDENTIAL_APPLICATION, SYNTHETIC_APPLICATION,
    },
    wire::{PairingIntent, Side},
};

fn intent(application: &str) -> PairingIntent {
    PairingIntent {
        application: application.into(),
        action: "profile-action".into(),
        allocator_claim: vec![0xa0],
        claimant_claim: vec![0xa0],
        authority_summary: "explicit approval required".into(),
        intent_nonce: [0x44; 32],
    }
}

#[test]
fn test_010_profiles_are_endpoint_local_and_describe_their_carriers() {
    let agent = AgentProfile::new();
    let credential = CredentialProfile::new();
    let synthetic = SyntheticProfile::new(true);

    assert_eq!(agent.descriptor().application, AGENT_APPLICATION);
    assert_eq!(agent.descriptor().carrier.locator, LocatorKind::Nameplate);
    assert_eq!(agent.descriptor().carrier.minimum_entropy_bits, 22);
    assert_eq!(credential.descriptor().application, CREDENTIAL_APPLICATION);
    assert_eq!(credential.descriptor().carrier.locator, LocatorKind::Direct);
    assert_eq!(credential.descriptor().carrier.minimum_entropy_bits, 128);
    assert_eq!(synthetic.descriptor().application, SYNTHETIC_APPLICATION);

    // The Red Gate is behavioural: all three profile recognisers execute and
    // must eventually accept their own fully formed intent.
    for (profile, application) in [
        (&agent as &dyn ApplicationProfile, AGENT_APPLICATION),
        (
            &credential as &dyn ApplicationProfile,
            CREDENTIAL_APPLICATION,
        ),
        (&synthetic as &dyn ApplicationProfile, SYNTHETIC_APPLICATION),
    ] {
        assert!(profile.recognise_intent(&intent(application)).is_ok());
    }

    let _fixed_side = Side::Allocator;
}
