//! SPEC-001 TEST-060 protected credential/v2 admission Red Gate.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    mailbox::{
        transition, AdmissionSnapshot, AllocationInput, Mailbox, MailboxCommand, MailboxError,
        MembershipHash, V2AllocationInput, V2_TTL_SECONDS,
    },
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService},
    storage::FileMailboxStore,
    wire::{
        claim_commitment, decode_client_message, decode_server_message, encode_client_message,
        encode_server_message, ClaimToken, ClientMessage, RecognitionError, ServerMessage,
    },
};
use ciborium::Value;
use std::{
    fs,
    io::Cursor,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_800_000_000;
const MAILBOX: [u8; 32] = [0x21; 32];
const OTHER_MAILBOX: [u8; 32] = [0x22; 32];
const CLAIM_TOKEN: [u8; 16] = [0x31; 16];
const ALLOCATOR_TOKEN: [u8; 32] = [0x41; 32];
const CLAIMANT_TOKEN: [u8; 32] = [0x51; 32];

fn hash(fill: u8) -> MembershipHash {
    MembershipHash::new([fill; 32])
}

fn token() -> ClaimToken {
    ClaimToken::new(CLAIM_TOKEN)
}

fn allocated_v2(mailbox_id: [u8; 32], ttl_seconds: Option<u16>) -> Mailbox {
    Mailbox::allocate_v2(V2AllocationInput {
        mailbox_id,
        allocator_hash: hash(0xa1),
        claim_commitment: claim_commitment(mailbox_id, &token()),
        now: NOW,
        ttl_seconds,
    })
    .expect("v2 mailbox allocates")
}

fn cbor_map(entries: Vec<(&str, Value)>) -> Vec<u8> {
    cbor2::to_canonical_vec(&Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::Text(key.into()), value))
            .collect(),
    ))
    .expect("test CBOR encodes")
}

#[test]
fn test_060_v2_wire_round_trips_without_changing_v1_variants() {
    let commitment = claim_commitment(MAILBOX, &token());
    assert_eq!(
        hex::encode(commitment),
        "dd09268186104aad2e2b1242c17a368c24a3c830a0edda07d528ec95c3a75dc2"
    );
    let clients = [
        ClientMessage::AllocateV2 {
            mailbox_id: MAILBOX,
            claim_commitment: commitment,
            ttl_seconds: None,
        },
        ClientMessage::AllocateV2 {
            mailbox_id: MAILBOX,
            claim_commitment: commitment,
            ttl_seconds: Some(V2_TTL_SECONDS),
        },
        ClientMessage::ClaimV2 {
            mailbox_id: MAILBOX,
            claim_token: token(),
        },
    ];
    for message in clients {
        let encoded = encode_client_message(&message).expect("v2 client encodes");
        assert_eq!(decode_client_message(&encoded), Ok(message));
    }

    let servers = [
        ServerMessage::AllocatedV2 {
            mailbox_id: MAILBOX,
            membership_token: ALLOCATOR_TOKEN,
            expires_at: NOW + u64::from(V2_TTL_SECONDS),
        },
        ServerMessage::ClaimedV2 {
            mailbox_id: MAILBOX,
            membership_token: CLAIMANT_TOKEN,
            expires_at: NOW + u64::from(V2_TTL_SECONDS),
        },
    ];
    for message in servers {
        let encoded = encode_server_message(&message).expect("v2 server encodes");
        assert_eq!(decode_server_message(&encoded), Ok(message));
    }
}

#[test]
fn test_060_v2_wire_accepts_only_exact_or_omitted_lifetime() {
    for refused in [599_u64, 600, 899, 901] {
        let encoded = cbor_map(vec![
            ("type", Value::Text("allocate-v2".into())),
            ("mailbox-id", Value::Bytes(MAILBOX.to_vec())),
            ("claim-commitment", Value::Bytes([0x61; 32].to_vec())),
            ("ttl-seconds", Value::Integer(refused.into())),
        ]);
        assert_eq!(
            decode_client_message(&encoded),
            Err(RecognitionError::Schema)
        );
    }

    let missing_token = cbor_map(vec![
        ("type", Value::Text("claim-v2".into())),
        ("mailbox-id", Value::Bytes(MAILBOX.to_vec())),
    ]);
    assert_eq!(
        decode_client_message(&missing_token),
        Err(RecognitionError::Schema)
    );

    let mut trailing = encode_client_message(&ClientMessage::ClaimV2 {
        mailbox_id: MAILBOX,
        claim_token: token(),
    })
    .expect("claim encodes");
    trailing.push(0);
    assert_eq!(
        decode_client_message(&trailing),
        Err(RecognitionError::TrailingBytes)
    );
}

#[test]
fn test_060_exact_bearer_claims_once_and_erases_commitment() {
    for refused in [599, 600, 899, 901] {
        assert_eq!(
            Mailbox::allocate_v2(V2AllocationInput {
                mailbox_id: MAILBOX,
                allocator_hash: hash(0xa1),
                claim_commitment: claim_commitment(MAILBOX, &token()),
                now: NOW,
                ttl_seconds: Some(refused),
            }),
            Err(MailboxError::LifetimeOutOfRange)
        );
    }
    let mailbox = allocated_v2(MAILBOX, None);
    assert_eq!(mailbox.expires_at(), NOW + u64::from(V2_TTL_SECONDS));
    assert!(matches!(
        mailbox.snapshot().admission,
        AdmissionSnapshot::V2Pending(_)
    ));

    let result = transition(
        &mailbox,
        NOW + 1,
        MailboxCommand::ClaimV2 {
            claimant_hash: hash(0xb2),
            claim_token: token(),
        },
    )
    .expect("exact bearer claims");
    let claimed = result.state.expect("claimed mailbox remains");
    assert_eq!(claimed.snapshot().admission, AdmissionSnapshot::V2Claimed);
    assert_eq!(claimed.snapshot().membership_hashes.len(), 2);

    assert_eq!(
        transition(
            &claimed,
            NOW + 2,
            MailboxCommand::ClaimV2 {
                claimant_hash: hash(0xc3),
                claim_token: token(),
            },
        ),
        Err(MailboxError::NotMember)
    );
}

#[test]
fn test_060_wrong_and_cross_mailbox_bearers_change_no_state() {
    let mailbox = allocated_v2(MAILBOX, Some(V2_TTL_SECONDS));
    let before = mailbox.snapshot();
    assert_eq!(
        transition(
            &mailbox,
            NOW + 1,
            MailboxCommand::ClaimV2 {
                claimant_hash: hash(0xb2),
                claim_token: ClaimToken::new([0x32; 16]),
            },
        ),
        Err(MailboxError::NotMember)
    );
    assert_eq!(mailbox.snapshot(), before);

    let other = Mailbox::allocate_v2(V2AllocationInput {
        mailbox_id: OTHER_MAILBOX,
        allocator_hash: hash(0xa1),
        claim_commitment: claim_commitment(MAILBOX, &token()),
        now: NOW,
        ttl_seconds: None,
    })
    .expect("cross-mailbox fixture allocates");
    let other_before = other.snapshot();
    assert_eq!(
        transition(
            &other,
            NOW + 1,
            MailboxCommand::ClaimV2 {
                claimant_hash: hash(0xb2),
                claim_token: token(),
            },
        ),
        Err(MailboxError::NotMember)
    );
    assert_eq!(other.snapshot(), other_before);

    let v1 = Mailbox::allocate(AllocationInput {
        mailbox_id: MAILBOX,
        nameplate: None,
        allocator_hash: hash(0xa1),
        now: NOW,
        ttl_seconds: None,
    })
    .expect("v1 mailbox");
    assert_eq!(
        transition(
            &v1,
            NOW + 1,
            MailboxCommand::ClaimV2 {
                claimant_hash: hash(0xb2),
                claim_token: token(),
            },
        ),
        Err(MailboxError::NotMember)
    );
    assert_eq!(
        transition(
            &mailbox,
            NOW + 1,
            MailboxCommand::Claim {
                claimant_hash: hash(0xb2),
            },
        ),
        Err(MailboxError::NotMember)
    );
    assert_eq!(format!("{:?}", token()), "ClaimToken(REDACTED)");
}

fn relay_config() -> RelayConfig {
    RelayConfig {
        operator_key: [0x71; 32],
        limiter: LimiterConfig::new(
            OperationPolicy {
                limit: 100,
                window_seconds: 60,
            },
            128,
            10,
        ),
        capacity: CapacityCaps {
            open_mailboxes: 16,
            queue_bytes: 1_000_000,
            limiter_entries: 128,
        },
        allocation_enabled: true,
    }
}

fn random(token: [u8; 32]) -> RelayRandomness {
    RelayRandomness {
        mailbox_id: [0; 32],
        membership_token: token,
        nameplate: 0,
    }
}

fn temporary_store() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cbcl-pairing-v2-admission-{}-{stamp}-{unique}",
        std::process::id()
    ))
}

fn stored_service(path: &PathBuf, allocation_enabled: bool) -> RelayService {
    let mut config = relay_config();
    config.allocation_enabled = allocation_enabled;
    RelayService::with_store(
        config,
        Box::new(FileMailboxStore::open(path).expect("store opens")),
    )
    .expect("stored relay starts")
}

fn bind_connection(relay: &mut RelayService, connection: u64, now: u64) {
    let result = relay
        .handle(
            ConnectionId(connection),
            b"test peer",
            now,
            random([0; 32]),
            ClientMessage::Bind,
        )
        .expect("bind succeeds");
    assert_eq!(result[0].message, ServerMessage::Welcome);
}

fn only_store_file(path: &PathBuf) -> PathBuf {
    let files: Vec<_> = fs::read_dir(path)
        .expect("read store")
        .map(|entry| entry.expect("store entry").path())
        .collect();
    assert_eq!(files.len(), 1);
    files[0].clone()
}

#[test]
fn test_060_relay_wrong_bearer_is_closed_unknown_and_exact_bearer_claims() {
    let mut relay = RelayService::new(relay_config()).expect("relay");
    relay
        .handle(
            ConnectionId(1),
            b"allocator",
            NOW,
            random([0; 32]),
            ClientMessage::Bind,
        )
        .expect("bind");
    let allocated = relay
        .handle(
            ConnectionId(1),
            b"allocator",
            NOW,
            random(ALLOCATOR_TOKEN),
            ClientMessage::AllocateV2 {
                mailbox_id: MAILBOX,
                claim_commitment: claim_commitment(MAILBOX, &token()),
                ttl_seconds: None,
            },
        )
        .expect("allocate");
    assert!(matches!(
        allocated[0].message,
        ServerMessage::AllocatedV2 {
            expires_at,
            ..
        } if expires_at == NOW + u64::from(V2_TTL_SECONDS)
    ));

    for (connection, claim_token, expected) in [
        (2, ClaimToken::new([0x32; 16]), ServerMessage::Error(404)),
        (
            3,
            token(),
            ServerMessage::ClaimedV2 {
                mailbox_id: MAILBOX,
                membership_token: CLAIMANT_TOKEN,
                expires_at: NOW + u64::from(V2_TTL_SECONDS),
            },
        ),
    ] {
        relay
            .handle(
                ConnectionId(connection),
                b"claimant",
                NOW + connection,
                random([0; 32]),
                ClientMessage::Bind,
            )
            .expect("bind claimant");
        let response = relay
            .handle(
                ConnectionId(connection),
                b"claimant",
                NOW + connection,
                random(CLAIMANT_TOKEN),
                ClientMessage::ClaimV2 {
                    mailbox_id: MAILBOX,
                    claim_token,
                },
            )
            .expect("claim response");
        assert_eq!(response[0].message, expected);
    }
}

#[test]
fn test_060_v2_pending_claimed_and_closed_states_restart_without_bearers() {
    let path = temporary_store();
    let commitment = claim_commitment(MAILBOX, &token());
    let mut relay = stored_service(&path, true);
    bind_connection(&mut relay, 1, NOW);
    relay
        .handle(
            ConnectionId(1),
            b"allocator",
            NOW,
            random(ALLOCATOR_TOKEN),
            ClientMessage::AllocateV2 {
                mailbox_id: MAILBOX,
                claim_commitment: commitment,
                ttl_seconds: None,
            },
        )
        .expect("allocate");
    drop(relay);

    let pending_bytes = fs::read(only_store_file(&path)).expect("pending record");
    assert!(!pending_bytes
        .windows(CLAIM_TOKEN.len())
        .any(|window| window == CLAIM_TOKEN));

    let mut relay = stored_service(&path, false);
    assert_eq!(relay.mailbox_count(), 1);
    bind_connection(&mut relay, 2, NOW + 1);
    let before_wrong = fs::read(only_store_file(&path)).expect("pending record");
    let wrong = relay
        .handle(
            ConnectionId(2),
            b"claimant",
            NOW + 1,
            random(CLAIMANT_TOKEN),
            ClientMessage::ClaimV2 {
                mailbox_id: MAILBOX,
                claim_token: ClaimToken::new([0x32; 16]),
            },
        )
        .expect("wrong claim refuses");
    assert_eq!(wrong[0].message, ServerMessage::Error(404));
    assert_eq!(
        fs::read(only_store_file(&path)).expect("pending record"),
        before_wrong
    );

    bind_connection(&mut relay, 3, NOW + 2);
    let exact = relay
        .handle(
            ConnectionId(3),
            b"claimant",
            NOW + 2,
            random(CLAIMANT_TOKEN),
            ClientMessage::ClaimV2 {
                mailbox_id: MAILBOX,
                claim_token: token(),
            },
        )
        .expect("exact claim succeeds");
    assert!(matches!(exact[0].message, ServerMessage::ClaimedV2 { .. }));
    drop(relay);

    let claimed_bytes = fs::read(only_store_file(&path)).expect("claimed record");
    assert!(!claimed_bytes
        .windows(commitment.len())
        .any(|window| window == commitment));
    assert!(!claimed_bytes
        .windows(CLAIM_TOKEN.len())
        .any(|window| window == CLAIM_TOKEN));

    let mut relay = stored_service(&path, false);
    assert_eq!(relay.mailbox_count(), 1);
    relay.emergency_close(NOW + 3).expect("close v2");
    drop(relay);

    let mut relay = stored_service(&path, false);
    assert_eq!(relay.mailbox_count(), 1);
    relay
        .sweep(NOW + u64::from(V2_TTL_SECONDS))
        .expect("original expiry reaps");
    assert_eq!(relay.mailbox_count(), 0);
    drop(relay);
    fs::remove_dir(&path).expect("remove empty store");
}

#[test]
fn test_060_inconsistent_v2_store_state_fails_startup() {
    let path = temporary_store();
    let mut relay = stored_service(&path, true);
    bind_connection(&mut relay, 1, NOW);
    relay
        .handle(
            ConnectionId(1),
            b"allocator",
            NOW,
            random(ALLOCATOR_TOKEN),
            ClientMessage::AllocateV2 {
                mailbox_id: MAILBOX,
                claim_commitment: claim_commitment(MAILBOX, &token()),
                ttl_seconds: None,
            },
        )
        .expect("allocate");
    drop(relay);

    let file = only_store_file(&path);
    let bytes = fs::read(&file).expect("read record");
    let mut value: Value = ciborium::de::from_reader(Cursor::new(bytes)).expect("decode record");
    let Value::Array(parts) = &mut value else {
        panic!("store record is array")
    };
    parts[4] = Value::Array(vec![Value::Integer(1.into())]);
    fs::write(
        &file,
        cbor2::to_canonical_vec(&value).expect("encode corruption"),
    )
    .expect("write corruption");

    let result = RelayService::with_store(
        relay_config(),
        Box::new(FileMailboxStore::open(&path).expect("store opens")),
    );
    assert!(result.is_err(), "inconsistent v2 record started");
    fs::remove_dir_all(&path).expect("remove corrupt store");
}
