//! SPEC-072 TEST-020 source, installation, hash, and projection baseline.

use cbcl_core::canonical::dialect_hash;
use cbcl_core::dialect::DialectRegistry;
use cbcl_core::projection::{project, LocalStep};
use cbcl_core::role::Endpoint;
use cbcl_pairing::{
    BOOTSTRAP_DIALECT_HASH, BOOTSTRAP_DIALECT_SOURCE, BOOTSTRAP_SOURCE_SHA256,
    SESSION_DIALECT_HASH, SESSION_DIALECT_SOURCE, SESSION_SOURCE_SHA256,
};
use cbcl_parser::dialect_parser::parse_dialect;
use sha2::{Digest, Sha256};

fn install(source: &str) -> (DialectRegistry, String) {
    let sexpr = cbcl_parser::parse(source).expect("normative source parses");
    let dialect = parse_dialect(&sexpr).expect("normative dialect recognises");
    let mut registry = DialectRegistry::new();
    let hash = dialect_hash(&dialect);
    registry
        .install(dialect)
        .expect("normative dialect installs");
    (registry, hash)
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

#[test]
fn test_020_exact_sources_and_canonical_hashes_match() {
    assert_eq!(
        sha256_hex(BOOTSTRAP_DIALECT_SOURCE.as_bytes()),
        BOOTSTRAP_SOURCE_SHA256
    );
    assert_eq!(
        sha256_hex(SESSION_DIALECT_SOURCE.as_bytes()),
        SESSION_SOURCE_SHA256
    );

    let (_, bootstrap_hash) = install(BOOTSTRAP_DIALECT_SOURCE);
    let (_, session_hash) = install(SESSION_DIALECT_SOURCE);
    assert_eq!(bootstrap_hash, BOOTSTRAP_DIALECT_HASH);
    assert_eq!(session_hash, SESSION_DIALECT_HASH);
}

#[test]
fn test_020_session_projections_are_complementary() {
    let (registry, _) = install(SESSION_DIALECT_SOURCE);
    let dialect = registry
        .find_by_name("blind-pairing-session/v1")
        .expect("installed session dialect");

    let allocator = project(
        dialect,
        &Endpoint {
            role: "allocator".into(),
            occupant: None,
        },
        None,
    );
    let claimant = project(
        dialect,
        &Endpoint {
            role: "claimant".into(),
            occupant: None,
        },
        None,
    );

    assert_eq!(
        allocator.steps.get("pairing-intent"),
        Some(&LocalStep::Send)
    );
    assert_eq!(
        allocator.steps.get("pairing-payload"),
        Some(&LocalStep::Send)
    );
    assert_eq!(
        allocator.steps.get("pairing-approve"),
        Some(&LocalStep::Recv)
    );
    assert_eq!(
        allocator.steps.get("pairing-decline"),
        Some(&LocalStep::Recv)
    );
    assert_eq!(claimant.steps.get("pairing-intent"), Some(&LocalStep::Recv));
    assert_eq!(
        claimant.steps.get("pairing-payload"),
        Some(&LocalStep::Recv)
    );
    assert_eq!(
        claimant.steps.get("pairing-approve"),
        Some(&LocalStep::Send)
    );
    assert_eq!(
        claimant.steps.get("pairing-decline"),
        Some(&LocalStep::Send)
    );
}
