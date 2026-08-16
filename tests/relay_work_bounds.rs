//! SPEC-001 TEST-024 relay work-amplification regression gate.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    mailbox::{transition, AllocationInput, Mailbox, MailboxCommand, Membership, MembershipHash},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayError, RelayRandomness, RelayService},
    storage::{MailboxStore, StoreError},
    wire::{ClientMessage, ServerMessage},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

const MAILBOXES: usize = 200;
const BODY_BYTES: usize = 69_632;
const FRAMES: u8 = 16;
const ALLOCATION_CEILING: usize = 64 * 1024;

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_allocation(bytes: usize) {
    TRACK_ALLOCATIONS.with(|tracking| {
        if tracking.get() {
            ALLOCATED_BYTES.with(|total| total.set(total.get().saturating_add(bytes)));
        }
    });
}

fn measure_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED_BYTES.with(|total| total.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let allocated = ALLOCATED_BYTES.with(Cell::get);
    (result, allocated)
}

struct SeedStore {
    mailboxes: Option<Vec<Mailbox>>,
}

impl MailboxStore for SeedStore {
    fn load(&mut self) -> Result<Vec<Mailbox>, StoreError> {
        Ok(self.mailboxes.take().unwrap_or_default())
    }

    fn put(&mut self, _mailbox: &Mailbox) -> Result<(), StoreError> {
        Ok(())
    }

    fn remove(&mut self, _mailbox_id: [u8; 32]) -> Result<(), StoreError> {
        Ok(())
    }
}

fn identity(index: usize) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[..8].copy_from_slice(&(index as u64).to_be_bytes());
    value
}

fn seeded_mailboxes() -> Vec<Mailbox> {
    (0..MAILBOXES)
        .map(|index| {
            let mut mailbox = Mailbox::allocate(AllocationInput {
                mailbox_id: identity(index),
                nameplate: None,
                allocator_hash: MembershipHash::new(identity(index + MAILBOXES)),
                now: 0,
                ttl_seconds: Some(600),
            })
            .expect("mailbox");
            for seq in 0..FRAMES {
                mailbox = transition(
                    &mailbox,
                    1,
                    MailboxCommand::Put {
                        sender: Membership::Allocator,
                        seq,
                        body: vec![seq; BODY_BYTES],
                    },
                )
                .expect("put")
                .state
                .expect("retained mailbox");
            }
            mailbox
        })
        .collect()
}

fn service() -> RelayService {
    let queued = MAILBOXES as u64 * u64::from(FRAMES) * BODY_BYTES as u64;
    RelayService::with_store(
        RelayConfig {
            operator_key: [0x55; 32],
            limiter: LimiterConfig::new(
                OperationPolicy {
                    limit: 100,
                    window_seconds: 60,
                },
                1_024,
                30,
            ),
            capacity: CapacityCaps {
                open_mailboxes: MAILBOXES as u64,
                queue_bytes: queued,
                limiter_entries: 1_024,
            },
            allocation_enabled: false,
        },
        Box::new(SeedStore {
            mailboxes: Some(seeded_mailboxes()),
        }),
    )
    .expect("seeded service")
}

fn small_mailbox(mailbox: u8, membership: u8, body: Option<Vec<u8>>) -> Mailbox {
    let mut mailbox = Mailbox::allocate(AllocationInput {
        mailbox_id: [mailbox; 32],
        nameplate: None,
        allocator_hash: MembershipHash::new([membership; 32]),
        now: 0,
        ttl_seconds: Some(600),
    })
    .expect("mailbox");
    if let Some(body) = body {
        mailbox = transition(
            &mailbox,
            1,
            MailboxCommand::Put {
                sender: Membership::Allocator,
                seq: 0,
                body,
            },
        )
        .expect("put")
        .state
        .expect("retained mailbox");
    }
    mailbox
}

fn restore(
    mailboxes: Vec<Mailbox>,
    open_mailboxes: u64,
    queue_bytes: u64,
) -> Result<RelayService, RelayError> {
    RelayService::with_store(
        RelayConfig {
            operator_key: [0x66; 32],
            limiter: LimiterConfig::new(
                OperationPolicy {
                    limit: 100,
                    window_seconds: 60,
                },
                16,
                30,
            ),
            capacity: CapacityCaps {
                open_mailboxes,
                queue_bytes,
                limiter_entries: 16,
            },
            allocation_enabled: false,
        },
        Box::new(SeedStore {
            mailboxes: Some(mailboxes),
        }),
    )
}

#[test]
fn test_024_ping_and_no_expiry_sweep_do_not_copy_queued_bodies() {
    let mut relay = service();
    let randomness = RelayRandomness {
        mailbox_id: [0; 32],
        membership_token: [0; 32],
        nameplate: 0,
    };
    relay
        .handle(
            ConnectionId(1),
            b"192.0.2.1",
            1,
            randomness,
            ClientMessage::Bind,
        )
        .expect("bind");
    let before = relay.metrics().gauges;
    assert!(before.queue_bytes >= 200 * 1024 * 1024);

    let (reply, ping_allocations) = measure_allocations(|| {
        relay.handle(
            ConnectionId(1),
            b"192.0.2.1",
            2,
            randomness,
            ClientMessage::Ping,
        )
    });
    assert_eq!(reply.expect("ping")[0].message, ServerMessage::Pong);
    assert!(
        ping_allocations < ALLOCATION_CEILING,
        "Ping allocated {ping_allocations} bytes"
    );

    let (expired, sweep_allocations) = measure_allocations(|| relay.sweep(2));
    assert!(expired.expect("sweep").is_empty());
    assert!(
        sweep_allocations < ALLOCATION_CEILING,
        "no-expiry sweep allocated {sweep_allocations} bytes"
    );
    let after = relay.metrics().gauges;
    assert_eq!(after.open_mailboxes, before.open_mailboxes);
    assert_eq!(after.queue_bytes, before.queue_bytes);
    assert_eq!(
        after.limiter_clock_reversals,
        before.limiter_clock_reversals
    );
    assert_eq!(before.limiter_entries, 1);
    assert_eq!(after.limiter_entries, 2);
}

#[test]
fn restored_indexes_reject_duplicate_memberships_and_independent_capacity_overflow() {
    assert!(matches!(
        restore(
            vec![small_mailbox(1, 9, None), small_mailbox(2, 9, None)],
            2,
            1,
        ),
        Err(RelayError::Storage)
    ));
    assert!(matches!(
        restore(
            vec![small_mailbox(1, 1, None), small_mailbox(2, 2, None)],
            1,
            1,
        ),
        Err(RelayError::InvalidConfiguration)
    ));
    assert!(matches!(
        restore(vec![small_mailbox(1, 1, Some(vec![1, 2]))], 1, 1),
        Err(RelayError::InvalidConfiguration)
    ));
}
