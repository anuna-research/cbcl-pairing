//! Behavioural Red Gate for the reference relay service.

use cbcl_pairing::{
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService},
    wire::ClientMessage,
};

fn config() -> RelayConfig {
    RelayConfig {
        operator_key: [0x11; 32],
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
        allocation_enabled: true,
    }
}

#[test]
fn test_017_reference_relay_composes_the_existing_cores() {
    let mut relay = RelayService::new(config()).expect("relay service");
    let replies = relay
        .handle(
            ConnectionId(1),
            b"127.0.0.1:10001",
            1_000,
            RelayRandomness {
                mailbox_id: [0x22; 32],
                membership_token: [0x33; 32],
                nameplate: 123,
            },
            ClientMessage::Bind,
        )
        .expect("bind");
    assert_eq!(replies.len(), 1);
}
