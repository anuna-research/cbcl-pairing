//! Conformance tests for the reference relay service and local TEST-017 path.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::{CapacityCaps, RelayOutcome},
    relay::{
        sample_nameplate, ConnectionId, RelayConfig, RelayError, RelayRandomness, RelayService,
        RoutedMessage,
    },
    wire::{ClientMessage, CloseReason, Locator, ServerMessage},
};

const MAILBOX_ID: [u8; 32] = [0x22; 32];
const ALLOCATOR_TOKEN: [u8; 32] = [0x33; 32];
const CLAIMANT_TOKEN: [u8; 32] = [0x44; 32];

fn config(operator_key: [u8; 32], allocation_enabled: bool) -> RelayConfig {
    RelayConfig {
        operator_key,
        limiter: LimiterConfig::new(
            OperationPolicy {
                limit: 100,
                window_seconds: 60,
            },
            1_024,
            30,
        ),
        capacity: CapacityCaps {
            open_mailboxes: 64,
            queue_bytes: 64 * 69_632,
            limiter_entries: 1_024,
        },
        allocation_enabled,
    }
}

fn randomness(mailbox: u8, token: u8, nameplate: u32) -> RelayRandomness {
    RelayRandomness {
        mailbox_id: [mailbox; 32],
        membership_token: [token; 32],
        nameplate,
    }
}

fn handle(
    relay: &mut RelayService,
    connection: u64,
    now: u64,
    random: RelayRandomness,
    message: ClientMessage,
) -> Vec<RoutedMessage> {
    relay
        .handle(ConnectionId(connection), b"127.0.0.1", now, random, message)
        .expect("relay command")
}

fn bind(relay: &mut RelayService, connection: u64, now: u64) {
    assert_eq!(
        handle(
            relay,
            connection,
            now,
            randomness(0, 0, 0),
            ClientMessage::Bind,
        ),
        vec![RoutedMessage {
            connection: ConnectionId(connection),
            message: ServerMessage::Welcome,
        }]
    );
}

#[test]
fn bind_is_mandatory_and_production_allocation_stays_disabled_by_default() {
    let mut relay = RelayService::new(config([0x11; 32], false)).expect("service");
    assert_eq!(
        handle(
            &mut relay,
            1,
            1_000,
            randomness(0x22, 0x33, 123),
            ClientMessage::Ping,
        )[0]
        .message,
        ServerMessage::Error(400)
    );
    bind(&mut relay, 1, 1_001);
    assert_eq!(
        handle(
            &mut relay,
            1,
            1_002,
            randomness(0x22, 0x33, 123),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: None,
            },
        )[0]
        .message,
        ServerMessage::Error(503)
    );
    assert_eq!(relay.mailbox_count(), 0);
    assert_eq!(
        relay.last_log_event().expect("closed log").outcome,
        RelayOutcome::Unavailable
    );
}

#[test]
fn queued_delivery_ack_reconnect_crowding_and_expiry_use_only_mailbox_semantics() {
    let mut relay = RelayService::new(config([0x11; 32], true)).expect("service");
    bind(&mut relay, 1, 1_000);
    let allocated = handle(
        &mut relay,
        1,
        1_001,
        RelayRandomness {
            mailbox_id: MAILBOX_ID,
            membership_token: ALLOCATOR_TOKEN,
            nameplate: 123,
        },
        ClientMessage::Allocate {
            locator_mode: 1,
            ttl_seconds: Some(60),
        },
    );
    assert!(matches!(
        allocated.as_slice(),
        [RoutedMessage {
            message: ServerMessage::Allocated {
                mailbox_id: MAILBOX_ID,
                membership_token: ALLOCATOR_TOKEN,
                nameplate: Some(123),
                expires_at: 1_061,
            },
            ..
        }]
    ));

    // Queue before the peer joins. The relay acknowledges but cannot inspect
    // or deliver until a claimant exists.
    let opaque_agent = b"opaque agent-profile ciphertext".to_vec();
    assert_eq!(
        handle(
            &mut relay,
            1,
            1_002,
            randomness(0, 0, 0),
            ClientMessage::Put {
                seq: 0,
                body: opaque_agent.clone(),
            },
        )[0]
        .message,
        ServerMessage::Acknowledged { seq: 0 }
    );

    bind(&mut relay, 2, 1_003);
    let claimed = handle(
        &mut relay,
        2,
        1_004,
        randomness(0, 0x44, 0),
        ClientMessage::Claim(Locator::Nameplate(123)),
    );
    assert!(matches!(
        claimed.as_slice(),
        [RoutedMessage {
            message: ServerMessage::Claimed {
                mailbox_id: MAILBOX_ID,
                membership_token: CLAIMANT_TOKEN,
                expires_at: 1_061,
            },
            ..
        }]
    ));

    // A connected put is routed only to the other membership.
    let opaque_credential = b"opaque credential-profile ciphertext".to_vec();
    let routed = handle(
        &mut relay,
        1,
        1_005,
        randomness(0, 0, 0),
        ClientMessage::Put {
            seq: 1,
            body: opaque_credential.clone(),
        },
    );
    assert!(routed.contains(&RoutedMessage {
        connection: ConnectionId(1),
        message: ServerMessage::Acknowledged { seq: 1 },
    }));
    assert!(routed.contains(&RoutedMessage {
        connection: ConnectionId(2),
        message: ServerMessage::Frame {
            peer_seq: 1,
            body: opaque_credential,
        },
    }));
    assert_eq!(routed.len(), 2);

    // Reopening with the claimant token resumes the same membership and
    // delivers both unacknowledged allocator frames byte-for-byte.
    relay.disconnect(ConnectionId(2));
    bind(&mut relay, 3, 1_006);
    let reopened = handle(
        &mut relay,
        3,
        1_007,
        randomness(0, 0, 0),
        ClientMessage::Open {
            mailbox_id: MAILBOX_ID,
            membership_token: CLAIMANT_TOKEN,
        },
    );
    assert_eq!(
        reopened,
        vec![
            RoutedMessage {
                connection: ConnectionId(3),
                message: ServerMessage::Frame {
                    peer_seq: 0,
                    body: opaque_agent,
                },
            },
            RoutedMessage {
                connection: ConnectionId(3),
                message: ServerMessage::Frame {
                    peer_seq: 1,
                    body: b"opaque credential-profile ciphertext".to_vec(),
                },
            },
        ]
    );
    // An Ack command is confirmed by silence: the `acknowledged` message is
    // reserved for the sender's own stored Put, and echoing it here is what
    // broke every live credential/v2 ceremony with a Counter refusal.
    assert!(
        handle(
            &mut relay,
            3,
            1_008,
            randomness(0, 0, 0),
            ClientMessage::Ack { peer_seq: 0 },
        )
        .is_empty(),
        "an Ack command must produce no acknowledged echo"
    );

    // A third distinct claim crowds the mailbox and notifies both live peers
    // plus the crowding connection.
    bind(&mut relay, 4, 1_009);
    let crowded = handle(
        &mut relay,
        4,
        1_010,
        randomness(0, 0x55, 0),
        ClientMessage::Claim(Locator::Direct(MAILBOX_ID)),
    );
    for connection in [1, 3, 4] {
        assert!(crowded.contains(&RoutedMessage {
            connection: ConnectionId(connection),
            message: ServerMessage::Closed(CloseReason::Crowded),
        }));
    }

    assert_eq!(relay.mailbox_count(), 1);
    relay.sweep(1_061).expect("original expiry");
    assert_eq!(relay.mailbox_count(), 0);
    assert_eq!(relay.metrics().gauges.queue_bytes, 0);
}

fn operator_transcript(operator_key: [u8; 32]) -> Vec<Vec<RoutedMessage>> {
    let mut relay = RelayService::new(config(operator_key, true)).expect("operator");
    let mut transcript = vec![
        handle(
            &mut relay,
            10,
            2_000,
            randomness(0, 0, 0),
            ClientMessage::Bind,
        ),
        handle(
            &mut relay,
            10,
            2_001,
            RelayRandomness {
                mailbox_id: MAILBOX_ID,
                membership_token: ALLOCATOR_TOKEN,
                nameplate: 321,
            },
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(60),
            },
        ),
        handle(
            &mut relay,
            11,
            2_002,
            randomness(0, 0, 0),
            ClientMessage::Bind,
        ),
        handle(
            &mut relay,
            11,
            2_003,
            randomness(0, 0x44, 0),
            ClientMessage::Claim(Locator::Direct(MAILBOX_ID)),
        ),
    ];
    for (seq, body) in [
        (0, b"agent-profile opaque bytes".to_vec()),
        (1, b"credential-profile opaque bytes".to_vec()),
    ] {
        transcript.push(handle(
            &mut relay,
            10,
            2_004 + u64::from(seq),
            randomness(0, 0, 0),
            ClientMessage::Put { seq, body },
        ));
    }
    assert_eq!(relay.mailbox_count(), 1);
    transcript
}

#[test]
fn test_017_two_isolated_operator_instances_have_identical_protocol_results() {
    let first = operator_transcript([0x11; 32]);
    let second = operator_transcript([0x99; 32]);
    assert_eq!(first, second);
}

#[test]
fn test_025_relay_admission_survives_backwards_wall_clock_step() {
    let mut relay = RelayService::new(config([0x11; 32], false)).expect("service");
    assert_eq!(relay.metrics().gauges.limiter_clock_reversals, 0);
    bind(&mut relay, 1, 1_000);
    assert_eq!(relay.metrics().gauges.limiter_entries, 1);
    assert_eq!(
        handle(&mut relay, 1, 970, randomness(0, 0, 0), ClientMessage::Ping,)[0].message,
        ServerMessage::Pong
    );
    assert_eq!(relay.metrics().gauges.limiter_entries, 2);
    assert_eq!(relay.metrics().gauges.limiter_clock_reversals, 1);
}

#[test]
fn test_025_periodic_service_sweep_respects_exact_interval_boundaries() {
    let mut equality = RelayService::new(config([0x11; 32], false)).expect("service");
    bind(&mut equality, 1, 1_000);
    equality.sweep(1_029).expect("pre-interval sweep");
    equality.sweep(1_059).expect("interval sweep");
    equality.sweep(1_060).expect("second pre-interval sweep");
    assert_eq!(equality.metrics().gauges.limiter_entries, 1);

    let mut inclusive = RelayService::new(config([0x22; 32], false)).expect("service");
    bind(&mut inclusive, 1, 1_000);
    inclusive.sweep(1_030).expect("exact-interval sweep");
    inclusive.sweep(1_059).expect("pre-interval sweep");
    inclusive.sweep(1_060).expect("next exact-interval sweep");
    assert_eq!(inclusive.metrics().gauges.limiter_entries, 0);
}

#[test]
fn relay_configuration_rejects_each_independent_capacity_error() {
    let mut zero_queue = config([0x11; 32], false);
    zero_queue.capacity.queue_bytes = 0;
    assert!(matches!(
        RelayService::new(zero_queue),
        Err(RelayError::InvalidConfiguration)
    ));

    let mut mismatched_limiter = config([0x11; 32], false);
    mismatched_limiter.capacity.limiter_entries -= 1;
    assert!(matches!(
        RelayService::new(mismatched_limiter),
        Err(RelayError::InvalidConfiguration)
    ));
}

#[test]
fn membership_token_reuse_and_projected_queue_overflow_fail_closed() {
    let mut relay = RelayService::new(config([0x11; 32], true)).expect("service");
    bind(&mut relay, 1, 1_000);
    assert!(matches!(
        handle(
            &mut relay,
            1,
            1_001,
            randomness(0x11, 0x33, 0),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(60),
            },
        )[0]
        .message,
        ServerMessage::Allocated { .. }
    ));
    bind(&mut relay, 2, 1_002);
    assert_eq!(
        handle(
            &mut relay,
            2,
            1_003,
            randomness(0x22, 0x33, 0),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(60),
            },
        )[0]
        .message,
        ServerMessage::Error(503)
    );
    assert_eq!(relay.mailbox_count(), 1);

    let mut bounded = config([0x22; 32], true);
    bounded.capacity.queue_bytes = 1;
    let mut bounded = RelayService::new(bounded).expect("bounded service");
    bind(&mut bounded, 1, 2_000);
    handle(
        &mut bounded,
        1,
        2_001,
        randomness(0x44, 0x55, 0),
        ClientMessage::Allocate {
            locator_mode: 0,
            ttl_seconds: Some(60),
        },
    );
    assert_eq!(
        handle(
            &mut bounded,
            1,
            2_002,
            randomness(0, 0, 0),
            ClientMessage::Put {
                seq: 0,
                body: vec![1, 2],
            },
        )[0]
        .message,
        ServerMessage::Error(503)
    );
    assert_eq!(bounded.metrics().gauges.queue_bytes, 0);
}

#[test]
fn test_028_nameplate_sampling_rejects_the_biased_tail() {
    let mut candidates = [4_000_000_000_u32, 3_999_999_999].into_iter();
    let sampled = sample_nameplate(|| candidates.next().ok_or("missing candidate"))
        .expect("second candidate is accepted");
    assert_eq!(sampled, 999_999_999);
    assert!(candidates.next().is_none());
}
