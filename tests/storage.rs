//! Durable relay-store, restart, and rollback coverage.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService},
    storage::FileMailboxStore,
    wire::{ClientMessage, Locator, ServerMessage},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const MAILBOX: [u8; 32] = [0x31; 32];
const ALLOCATOR_TOKEN: [u8; 32] = [0x41; 32];
const CLAIMANT_TOKEN: [u8; 32] = [0x51; 32];

fn config(allocation_enabled: bool) -> RelayConfig {
    RelayConfig {
        operator_key: [0x61; 32],
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
        allocation_enabled,
    }
}

fn random(mailbox_id: [u8; 32], token: [u8; 32]) -> RelayRandomness {
    RelayRandomness {
        mailbox_id,
        membership_token: token,
        nameplate: 234_567_890,
    }
}

fn command(
    relay: &mut RelayService,
    connection: u64,
    now: u64,
    randomness: RelayRandomness,
    message: ClientMessage,
) -> Vec<ServerMessage> {
    relay
        .handle(
            ConnectionId(connection),
            b"192.0.2.10",
            now,
            randomness,
            message,
        )
        .expect("relay operation")
        .into_iter()
        .filter(|routed| routed.connection == ConnectionId(connection))
        .map(|routed| routed.message)
        .collect()
}

fn bind(relay: &mut RelayService, connection: u64, now: u64) {
    assert_eq!(
        command(
            relay,
            connection,
            now,
            random([0; 32], [0; 32]),
            ClientMessage::Bind
        ),
        vec![ServerMessage::Welcome]
    );
}

fn temporary_store() -> PathBuf {
    // The tests in this file run as parallel threads of one process, so the
    // process id is shared and the clock is the only thing separating their
    // store directories. `as_nanos` reports nanoseconds but is not guaranteed
    // to advance that finely, so two tests starting together can be handed the
    // same stamp and then race on the same directory. The counter makes the
    // name unique regardless of clock resolution.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cbcl-pairing-store-{}-{stamp}-{unique}",
        std::process::id()
    ))
}

fn service(path: &PathBuf, allocation: bool) -> RelayService {
    RelayService::with_store(
        config(allocation),
        Box::new(FileMailboxStore::open(path).expect("open store")),
    )
    .expect("load relay")
}

#[test]
fn durable_store_resumes_queue_ack_terminal_and_original_expiry() {
    let path = temporary_store();
    let mut relay = service(&path, true);
    bind(&mut relay, 1, 100);
    let allocated = command(
        &mut relay,
        1,
        100,
        random(MAILBOX, ALLOCATOR_TOKEN),
        ClientMessage::Allocate {
            locator_mode: 0,
            ttl_seconds: Some(60),
        },
    );
    assert!(
        matches!(allocated.as_slice(), [ServerMessage::Allocated { mailbox_id, .. }] if mailbox_id == &MAILBOX)
    );
    bind(&mut relay, 2, 101);
    assert!(matches!(
        command(
            &mut relay,
            2,
            101,
            random([0; 32], CLAIMANT_TOKEN),
            ClientMessage::Claim(Locator::Direct(MAILBOX)),
        )
        .as_slice(),
        [ServerMessage::Claimed { .. }]
    ));
    relay.disconnect(ConnectionId(2));
    assert_eq!(
        command(
            &mut relay,
            1,
            102,
            random([0; 32], [0; 32]),
            ClientMessage::Put {
                seq: 0,
                body: b"opaque queued frame".to_vec()
            },
        ),
        vec![ServerMessage::Acknowledged { seq: 0 }]
    );
    drop(relay);

    let files: Vec<_> = fs::read_dir(&path).unwrap().collect();
    assert_eq!(files.len(), 1);
    let stored = fs::read(files[0].as_ref().unwrap().path()).unwrap();
    assert!(!stored
        .windows(ALLOCATOR_TOKEN.len())
        .any(|window| window == ALLOCATOR_TOKEN));
    assert!(!stored
        .windows(CLAIMANT_TOKEN.len())
        .any(|window| window == CLAIMANT_TOKEN));

    let mut relay = service(&path, false);
    assert_eq!(relay.mailbox_count(), 1);
    bind(&mut relay, 3, 103);
    assert_eq!(
        command(
            &mut relay,
            3,
            103,
            random([0; 32], [0; 32]),
            ClientMessage::Open {
                mailbox_id: MAILBOX,
                membership_token: CLAIMANT_TOKEN
            },
        ),
        vec![ServerMessage::Frame {
            peer_seq: 0,
            body: b"opaque queued frame".to_vec()
        }]
    );
    assert_eq!(
        command(
            &mut relay,
            3,
            104,
            random([0; 32], [0; 32]),
            ClientMessage::Ack { peer_seq: 0 },
        ),
        vec![ServerMessage::Acknowledged { seq: 0 }]
    );
    drop(relay);

    let mut relay = service(&path, false);
    bind(&mut relay, 4, 105);
    assert!(
        command(
            &mut relay,
            4,
            105,
            random([0; 32], [0; 32]),
            ClientMessage::Open {
                mailbox_id: MAILBOX,
                membership_token: CLAIMANT_TOKEN
            },
        )
        .is_empty(),
        "acknowledged body did not reappear after restart"
    );
    let closed = relay.emergency_close(106).expect("operator close");
    assert!(closed
        .iter()
        .any(|routed| routed.message
            == ServerMessage::Closed(cbcl_pairing::wire::CloseReason::Closed)));
    drop(relay);

    let mut relay = service(&path, false);
    assert_eq!(
        relay.mailbox_count(),
        1,
        "terminal tombstone survives only to original expiry"
    );
    relay.sweep(160).expect("original expiry");
    assert_eq!(relay.mailbox_count(), 0);
    drop(relay);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    fs::remove_dir(&path).unwrap();
}

#[test]
fn runtime_kill_switch_refuses_new_allocation_without_closing_existing_mailbox() {
    let path = temporary_store();
    let mut relay = service(&path, true);
    bind(&mut relay, 1, 1);
    let _ = command(
        &mut relay,
        1,
        1,
        random(MAILBOX, ALLOCATOR_TOKEN),
        ClientMessage::Allocate {
            locator_mode: 0,
            ttl_seconds: Some(60),
        },
    );
    relay.disable_allocation();
    bind(&mut relay, 2, 2);
    assert_eq!(
        command(
            &mut relay,
            2,
            2,
            random([0x72; 32], [0x73; 32]),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(60)
            },
        ),
        vec![ServerMessage::Error(503)]
    );
    assert_eq!(relay.mailbox_count(), 1);
    drop(relay);
    fs::remove_dir_all(&path).unwrap();
}

#[test]
fn restart_deletes_interrupted_atomic_temporary_records() {
    let path = temporary_store();
    fs::create_dir_all(&path).unwrap();
    let temporary = path.join(format!(".{}.999.tmp", "31".repeat(32)));
    fs::write(&temporary, b"opaque body left by interrupted replacement").unwrap();
    let relay = service(&path, false);
    assert_eq!(relay.mailbox_count(), 0);
    assert!(
        !temporary.exists(),
        "untracked body-bearing temporary removed"
    );
    drop(relay);
    fs::remove_dir(&path).unwrap();
}
