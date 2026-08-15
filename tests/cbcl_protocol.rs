//! SPEC-072 TEST-020 protocol-adapter Red Gate and focused admission cases.

use cbcl_core::message::{CausedBy, Message, WrapperType};
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_pairing::cbcl_protocol::{
    build_bootstrap_control, build_session_control, build_session_opener, ceremony_id,
    encode_control, BootstrapMonitor, BootstrapPerformative, CeremonyKeyId, CeremonySigningKey,
    PairingDialects, PairingRole, ProtocolError, ProtocolVerdict, SessionMonitor,
    SessionPerformative,
};
use cbcl_pairing::{BOOTSTRAP_DIALECT_SOURCE, SESSION_DIALECT_HASH, SESSION_DIALECT_SOURCE};

const INVITATION: &[u8] = b"SPEC-072 deterministic invitation fixture";

fn keys() -> (CeremonySigningKey, CeremonySigningKey) {
    (
        CeremonySigningKey::from_secret([0x11; 32]).expect("allocator key"),
        CeremonySigningKey::from_secret([0x22; 32]).expect("claimant key"),
    )
}

fn bootstrap_prefix(
    monitor: &mut BootstrapMonitor,
    allocator: &CeremonySigningKey,
    claimant: &CeremonySigningKey,
) -> (String, String) {
    let ceremony = ceremony_id(INVITATION);
    let a_body = b"allocator CPace share";
    let b_body = b"claimant CPace share";
    let a = build_bootstrap_control(
        allocator,
        BootstrapPerformative::CpaceA,
        &ceremony,
        a_body,
        CausedBy::Begin,
    )
    .expect("build cpace-a");
    let b = build_bootstrap_control(
        claimant,
        BootstrapPerformative::CpaceB,
        &ceremony,
        b_body,
        CausedBy::Begin,
    )
    .expect("build cpace-b");
    let ah = monitor
        .admit(BootstrapPerformative::CpaceA, &a, a_body)
        .expect("admit cpace-a")
        .content_hash()
        .to_owned();
    let bh = monitor
        .admit(BootstrapPerformative::CpaceB, &b, b_body)
        .expect("admit cpace-b")
        .content_hash()
        .to_owned();
    (ah, bh)
}

fn opened_session(
    role: PairingRole,
) -> (
    SessionMonitor,
    CeremonySigningKey,
    CeremonySigningKey,
    CeremonyKeyId,
    CeremonyKeyId,
) {
    let (allocator, claimant) = keys();
    let allocator_id = allocator.key_id();
    let claimant_id = claimant.key_id();
    let opener = build_session_opener(&allocator, &claimant_id, &ceremony_id(INVITATION))
        .expect("build opener");
    let (monitor, admitted) =
        SessionMonitor::open(INVITATION, role, &allocator_id, &claimant_id, &opener)
            .expect("open session");
    assert_eq!(admitted.verdict(), ProtocolVerdict::Valid);
    assert_eq!(monitor.root_hash(), admitted.content_hash());
    (monitor, allocator, claimant, allocator_id, claimant_id)
}

#[test]
fn test_020_dialects_install_only_at_exact_sources_and_hashes() {
    PairingDialects::install().expect("embedded dialects install");
    PairingDialects::install_sources(BOOTSTRAP_DIALECT_SOURCE, SESSION_DIALECT_SOURCE)
        .expect("exact supplied dialects install");

    let mutated = BOOTSTRAP_DIALECT_SOURCE.replacen("max-depth 8", "max-depth 0", 1);
    assert_eq!(
        PairingDialects::install_sources(&mutated, SESSION_DIALECT_SOURCE).unwrap_err(),
        ProtocolError::Dialect
    );
}

#[test]
fn test_020_ceremony_keys_sign_canonical_controls_and_detect_mutation() {
    let (allocator, _) = keys();
    let ceremony = ceremony_id(INVITATION);
    assert_eq!(ceremony.len(), 64);
    assert!(ceremony
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert!(allocator.key_id().as_str().starts_with("@ed25519:"));
    assert_eq!(allocator.key_id().as_str().len(), 9 + 64);

    let body = b"share";
    let control = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::CpaceA,
        &ceremony,
        body,
        CausedBy::Begin,
    )
    .expect("build control");
    assert_eq!(
        control.last(),
        Some(&b')'),
        "canonical control has no trailing data"
    );

    let mut monitor = BootstrapMonitor::new(INVITATION).expect("monitor");
    let admission = monitor
        .admit(BootstrapPerformative::CpaceA, &control, body)
        .expect("valid signature");
    assert_eq!(admission.verdict(), ProtocolVerdict::Valid);
    assert!(admission.content_hash().starts_with("sha256:"));
    assert_eq!(admission.signer(), &allocator.key_id());

    let mut noncanonical = control.clone();
    noncanonical.push(b'\n');
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::CpaceA, &noncanonical, body)
            .unwrap_err(),
        ProtocolError::MalformedControl
    );

    let mut bad_signature = control;
    let first_quote = bad_signature
        .iter()
        .position(|b| *b == b'"')
        .expect("signature string");
    bad_signature[first_quote + 1] = if bad_signature[first_quote + 1] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::CpaceA, &bad_signature, body)
            .unwrap_err(),
        ProtocolError::Signature
    );
}

#[test]
fn test_021_finished_is_unknown_until_both_cpace_controls_exist() {
    let (allocator, claimant) = keys();
    let ceremony = ceremony_id(INVITATION);
    let a_body = b"a-share";
    let b_body = b"b-share";
    let mut monitor = BootstrapMonitor::new(INVITATION).expect("monitor");
    let a = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::CpaceA,
        &ceremony,
        a_body,
        CausedBy::Begin,
    )
    .expect("a");
    let ah = monitor
        .admit(BootstrapPerformative::CpaceA, &a, a_body)
        .expect("admit a")
        .content_hash()
        .to_owned();

    let missing_b = format!("sha256:{}", "7".repeat(64));
    let finished_body = b"finished-a";
    let early = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::FinishedA,
        &ceremony,
        finished_body,
        CausedBy::Multiple(vec![ah.clone(), missing_b]),
    )
    .expect("early finished");
    let early_admission = monitor
        .admit(BootstrapPerformative::FinishedA, &early, finished_body)
        .expect("well-formed but unresolved");
    assert_eq!(early_admission.verdict(), ProtocolVerdict::Unknown);
    assert_eq!(monitor.stored_count(), 1, "Unknown has zero store effects");

    let b = build_bootstrap_control(
        &claimant,
        BootstrapPerformative::CpaceB,
        &ceremony,
        b_body,
        CausedBy::Begin,
    )
    .expect("b");
    let bh = monitor
        .admit(BootstrapPerformative::CpaceB, &b, b_body)
        .expect("admit b")
        .content_hash()
        .to_owned();
    let finished = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::FinishedA,
        &ceremony,
        finished_body,
        CausedBy::Multiple(vec![ah, bh]),
    )
    .expect("resolved finished");
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::FinishedA, &finished, finished_body)
            .expect("admit finished")
            .verdict(),
        ProtocolVerdict::Valid
    );
    assert_eq!(monitor.stored_count(), 3);
}

#[test]
fn test_020_bootstrap_mapping_body_thread_and_key_are_pre_store_gates() {
    let (allocator, claimant) = keys();
    let ceremony = ceremony_id(INVITATION);
    let body = b"share";

    let good = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::CpaceA,
        &ceremony,
        body,
        CausedBy::Begin,
    )
    .expect("good");
    let mut monitor = BootstrapMonitor::new(INVITATION).expect("monitor");
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::CpaceB, &good, body)
            .unwrap_err(),
        ProtocolError::Performative
    );
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::CpaceA, &good, b"changed")
            .unwrap_err(),
        ProtocolError::BodyBinding
    );

    let wrong_thread = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::CpaceA,
        &"0".repeat(64),
        body,
        CausedBy::Begin,
    )
    .expect("wrong thread control");
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::CpaceA, &wrong_thread, body)
            .unwrap_err(),
        ProtocolError::Thread
    );

    monitor
        .admit(BootstrapPerformative::CpaceA, &good, body)
        .expect("establish allocator key");
    let changed_key = build_bootstrap_control(
        &claimant,
        BootstrapPerformative::FinishedA,
        &ceremony,
        b"finished",
        CausedBy::Multiple(vec![
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
        ]),
    )
    .expect("wrong role key");
    assert_eq!(
        monitor
            .admit(BootstrapPerformative::FinishedA, &changed_key, b"finished")
            .unwrap_err(),
        ProtocolError::KeyBinding
    );
    assert_eq!(monitor.stored_count(), 1);
}

#[test]
fn test_021_exact_role_opener_is_the_only_session_root() {
    let (allocator, claimant) = keys();
    let aid = allocator.key_id();
    let cid = claimant.key_id();
    let ceremony = ceremony_id(INVITATION);
    let opener = build_session_opener(&allocator, &cid, &ceremony).expect("opener");
    let (monitor, admission) =
        SessionMonitor::open(INVITATION, PairingRole::Allocator, &aid, &cid, &opener)
            .expect("open");
    assert_eq!(admission.verdict(), ProtocolVerdict::Valid);
    assert_eq!(monitor.stored_count(), 1);
    assert_eq!(monitor.root_hash(), admission.content_hash());

    let (_, other_claimant) = (
        CeremonySigningKey::from_secret([0x33; 32]).expect("other"),
        CeremonySigningKey::from_secret([0x44; 32]).expect("other claimant"),
    );
    assert_eq!(
        SessionMonitor::open(
            INVITATION,
            PairingRole::Allocator,
            &aid,
            &other_claimant.key_id(),
            &opener,
        )
        .unwrap_err(),
        ProtocolError::RoleOpener
    );
}

#[test]
fn test_020_opener_pin_is_exact_and_signature_checked() {
    let (allocator, claimant) = keys();
    let ceremony = ceremony_id(INVITATION);
    let hello: Message = Message::try_from(
        &format!("(hello :thread \"{ceremony}\" :caused-by begin)")
            .parse::<SExpr>()
            .expect("hello syntax"),
    )
    .expect("hello message");
    let signed = allocator.sign_message(hello).expect("sign hello");
    let wrong_pin = format!("sha256:{}", "0".repeat(64));
    assert_ne!(wrong_pin, SESSION_DIALECT_HASH);
    let bindings: SExpr = format!(
        "((allocator {}) (claimant {}))",
        allocator.key_id().as_str(),
        claimant.key_id().as_str()
    )
    .parse()
    .expect("bindings");
    let outer = Message::Wrapped {
        wrapper: WrapperType::WithRoles,
        params: vec![
            bindings,
            SExpr::Atom(Atom::Keyword("dialect".into())),
            SExpr::Atom(Atom::Symbol(wrong_pin)),
        ],
        content: Box::new(signed),
    };
    let control = encode_control(&outer).expect("canonical control");
    assert_eq!(
        SessionMonitor::open(
            INVITATION,
            PairingRole::Claimant,
            &allocator.key_id(),
            &claimant.key_id(),
            &control,
        )
        .unwrap_err(),
        ProtocolError::RoleOpener
    );
}

#[test]
fn test_022_sibling_decisions_each_have_a_valid_causal_verdict() {
    let (mut monitor, allocator, claimant, allocator_id, claimant_id) =
        opened_session(PairingRole::Allocator);
    let ceremony = ceremony_id(INVITATION);
    let intent_body = b"canonical pairing intent";
    let intent = build_session_control(
        &allocator,
        SessionPerformative::Intent,
        &ceremony,
        &claimant_id,
        intent_body,
        CausedBy::Single(monitor.root_hash().to_owned()),
    )
    .expect("intent");
    let ih = monitor
        .admit(SessionPerformative::Intent, &intent, intent_body)
        .expect("valid intent")
        .content_hash()
        .to_owned();

    let approve_body = b"approve decision";
    let approve = build_session_control(
        &claimant,
        SessionPerformative::Approve,
        &ceremony,
        &allocator_id,
        approve_body,
        CausedBy::Single(ih.clone()),
    )
    .expect("approve");
    let decline_body = b"decline decision";
    let decline = build_session_control(
        &claimant,
        SessionPerformative::Decline,
        &ceremony,
        &allocator_id,
        decline_body,
        CausedBy::Single(ih),
    )
    .expect("decline");
    assert_eq!(
        monitor
            .admit(SessionPerformative::Approve, &approve, approve_body)
            .expect("approve verdict")
            .verdict(),
        ProtocolVerdict::Valid
    );
    assert_eq!(
        monitor
            .admit(SessionPerformative::Decline, &decline, decline_body)
            .expect("decline verdict")
            .verdict(),
        ProtocolVerdict::Valid,
        "generic CBCL deliberately leaves atomic decision uniqueness to the reducer"
    );
}

#[test]
fn test_020_session_sender_recipient_predecessor_and_body_mutants_fail() {
    let (mut monitor, allocator, _claimant, allocator_id, claimant_id) =
        opened_session(PairingRole::Claimant);
    let ceremony = ceremony_id(INVITATION);
    let body = b"intent";
    let root = monitor.root_hash().to_owned();
    let good = build_session_control(
        &allocator,
        SessionPerformative::Intent,
        &ceremony,
        &claimant_id,
        body,
        CausedBy::Single(root.clone()),
    )
    .expect("good intent");
    assert_eq!(
        monitor
            .admit(SessionPerformative::Intent, &good, b"tampered")
            .unwrap_err(),
        ProtocolError::BodyBinding
    );

    let bad_recipient = build_session_control(
        &allocator,
        SessionPerformative::Intent,
        &ceremony,
        &allocator_id,
        body,
        CausedBy::Single(root.clone()),
    )
    .expect("bad recipient");
    assert_eq!(
        monitor
            .admit(SessionPerformative::Intent, &bad_recipient, body)
            .expect("role verdict")
            .verdict(),
        ProtocolVerdict::Violation
    );

    let bad_predecessor = build_session_control(
        &allocator,
        SessionPerformative::Intent,
        &ceremony,
        &claimant_id,
        body,
        CausedBy::Begin,
    )
    .expect("bad predecessor");
    assert_eq!(
        monitor
            .admit(SessionPerformative::Intent, &bad_predecessor, body)
            .expect("causal verdict")
            .verdict(),
        ProtocolVerdict::Violation
    );
    assert_eq!(
        monitor.stored_count(),
        1,
        "no rejected mutant reaches the store"
    );
}

#[test]
fn exact_duplicate_admission_is_idempotent() {
    let (allocator, claimant) = keys();
    let mut monitor = BootstrapMonitor::new(INVITATION).expect("monitor");
    let ceremony = ceremony_id(INVITATION);
    let body = b"a";
    let control = build_bootstrap_control(
        &allocator,
        BootstrapPerformative::CpaceA,
        &ceremony,
        body,
        CausedBy::Begin,
    )
    .expect("control");
    let first = monitor
        .admit(BootstrapPerformative::CpaceA, &control, body)
        .expect("first");
    let replay = monitor
        .admit(BootstrapPerformative::CpaceA, &control, body)
        .expect("replay");
    assert_eq!(first, replay);
    assert_eq!(monitor.stored_count(), 1);

    // Keep both key constructors used in this focused replay test.
    assert_ne!(allocator.key_id(), claimant.key_id());
}

#[test]
fn both_finished_controls_are_accepted_after_the_fan_in() {
    let (allocator, claimant) = keys();
    let mut monitor = BootstrapMonitor::new(INVITATION).expect("monitor");
    let (ah, bh) = bootstrap_prefix(&mut monitor, &allocator, &claimant);
    let ceremony = ceremony_id(INVITATION);
    let predecessors = CausedBy::Multiple(vec![ah, bh]);
    for (kind, key, body) in [
        (
            BootstrapPerformative::FinishedA,
            &allocator,
            b"finished-a".as_slice(),
        ),
        (
            BootstrapPerformative::FinishedB,
            &claimant,
            b"finished-b".as_slice(),
        ),
    ] {
        let control = build_bootstrap_control(key, kind, &ceremony, body, predecessors.clone())
            .expect("finished control");
        assert_eq!(
            monitor
                .admit(kind, &control, body)
                .expect("admit")
                .verdict(),
            ProtocolVerdict::Valid
        );
    }
    assert_eq!(monitor.stored_count(), 4);
}
