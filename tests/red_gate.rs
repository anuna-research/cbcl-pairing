//! Behavioural Red Gate for the unimplemented SPEC-072 components.

use cbcl_pairing::{component_status, ComponentStatus};

const COMPONENTS: &[&str] = &[
    "canonical-recognisers",
    "mailbox-core",
    "limiter-observability",
    "cpace-core",
    "secure-channel",
    "cbcl-protocol",
    "endpoint-reducer",
    "application-profiles",
    "relay-service",
];

#[test]
fn spec_072_components_are_implemented() {
    for component in COMPONENTS {
        assert_eq!(
            component_status(component),
            ComponentStatus::Implemented,
            "{component} remains a real behavioural stub"
        );
    }
}
