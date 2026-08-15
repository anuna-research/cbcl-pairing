//! SPEC-072 TEST-014 and TEST-015 detailed Red and Green Gate.

use cbcl_pairing::{
    limiter::{
        LimitDecision, Limiter, LimiterConfig, Operation, OperationPolicy, COOLDOWN_SECONDS,
    },
    observability::{CapacityCaps, RelayGauges, RelayObservability, RelayOutcome},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const OPERATOR_KEY: [u8; 32] = [0x55; 32];

fn config(entry_cap: usize) -> LimiterConfig {
    LimiterConfig::new(
        OperationPolicy {
            limit: 2,
            window_seconds: 10,
        },
        entry_cap,
        5,
    )
}

#[test]
fn test_014_logs_and_metrics_have_only_closed_non_sensitive_dimensions() {
    let raw_address = b"203.0.113.42:443";
    let sensitive_values = [
        "203.0.113.42:443",
        "123456789",
        "membership-token",
        "anuna.io/agent/v1",
        "claimed identity",
        "opaque body",
        "transcript digest",
    ];
    let mut limiter = Limiter::new(OPERATOR_KEY, config(16)).expect("limiter constructs");
    assert!(matches!(
        limiter.check(Operation::Bind, raw_address, 1),
        Ok(LimitDecision::Allowed { .. })
    ));

    let mut observability = RelayObservability::new(CapacityCaps {
        open_mailboxes: 100,
        queue_bytes: 1_000,
        limiter_entries: 10,
    });
    let cases = [
        (Operation::Allocate, RelayOutcome::Success),
        (Operation::Open, RelayOutcome::Invalid),
        (Operation::Claim, RelayOutcome::Crowded),
        (Operation::Open, RelayOutcome::Expired),
        (Operation::Put, RelayOutcome::RateLimited),
    ];
    for (operation, outcome) in cases {
        let event = observability.record(operation, outcome);
        assert_eq!(event.operation, operation);
        assert_eq!(event.outcome, outcome);
    }
    observability.set_gauges(RelayGauges {
        open_mailboxes: 80,
        queue_bytes: 799,
        limiter_entries: 8,
    });
    let metrics = observability.metrics();
    assert_eq!(metrics.operations.len(), cases.len());
    assert!(metrics.alerts.open_mailboxes);
    assert!(!metrics.alerts.queue_bytes);
    assert!(metrics.alerts.limiter_entries);

    let inspectable = format!("{limiter:?} {metrics:?}").to_ascii_lowercase();
    for sensitive in sensitive_values {
        assert!(!inspectable.contains(sensitive), "retained {sensitive}");
    }
}

#[test]
fn test_015_keyed_dimensions_have_independent_budgets_and_fixed_cooldown() {
    let address = b"198.51.100.7:8443";
    let mut limiter = Limiter::new(OPERATOR_KEY, config(32)).expect("limiter constructs");

    assert_eq!(
        limiter.check(Operation::Put, address, 100),
        Ok(LimitDecision::Allowed { remaining: 1 })
    );
    assert_eq!(
        limiter.check(Operation::Put, address, 101),
        Ok(LimitDecision::Allowed { remaining: 0 })
    );
    assert_eq!(
        limiter.check(Operation::Put, address, 102),
        Ok(LimitDecision::Cooldown {
            retry_at: 102 + COOLDOWN_SECONDS,
        })
    );
    assert_eq!(
        limiter.check(Operation::Ack, address, 102),
        Ok(LimitDecision::Allowed { remaining: 1 })
    );
    assert_eq!(
        limiter.check(Operation::Put, address, 401),
        Ok(LimitDecision::Cooldown { retry_at: 402 })
    );
    assert_eq!(
        limiter.check(Operation::Put, address, 402),
        Ok(LimitDecision::Allowed { remaining: 1 })
    );

    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.entry_count, 1);
    let put_key = snapshot
        .dimensions
        .iter()
        .find(|(operation, _)| *operation == Operation::Put)
        .expect("put dimension")
        .1;
    let mut expected = Hmac::<Sha256>::new_from_slice(&OPERATOR_KEY).expect("HMAC key");
    expected.update(address);
    assert_eq!(
        put_key.into_bytes().as_slice(),
        expected.finalize().into_bytes().as_slice()
    );
}

#[test]
fn test_015_every_operation_is_limited_and_entry_cap_survives_churn() {
    let mut limiter =
        Limiter::new(OPERATOR_KEY, config(Operation::ALL.len())).expect("limiter constructs");

    for (index, operation) in Operation::ALL.into_iter().enumerate() {
        let address = format!("192.0.2.{}:443", index + 1);
        let base = index as u64 * 3 + 1;
        assert!(matches!(
            limiter.check(operation, address.as_bytes(), base),
            Ok(LimitDecision::Allowed { .. })
        ));
        assert!(matches!(
            limiter.check(operation, address.as_bytes(), base + 1),
            Ok(LimitDecision::Allowed { .. })
        ));
        assert_eq!(
            limiter.check(operation, address.as_bytes(), base + 2),
            Ok(LimitDecision::Cooldown {
                retry_at: base + 2 + COOLDOWN_SECONDS,
            })
        );
    }
    assert_eq!(limiter.snapshot().entry_count, Operation::ALL.len());
    assert_eq!(
        limiter.check(Operation::Bind, b"192.0.2.250:443", 25),
        Ok(LimitDecision::AtCapacity)
    );
    assert_eq!(limiter.snapshot().entry_count, Operation::ALL.len());

    assert_eq!(limiter.sweep(302).expect("cooldowns remain"), 0);
    assert_eq!(
        limiter.sweep(334).expect("inactive entries sweep"),
        Operation::ALL.len()
    );
    assert_eq!(limiter.snapshot().entry_count, 0);
    assert!(matches!(
        limiter.check(Operation::Bind, b"192.0.2.250:443", 334),
        Ok(LimitDecision::Allowed { .. })
    ));
}

#[test]
fn test_015_periodic_sweep_runs_before_capacity_refusal() {
    let mut limiter = Limiter::new(OPERATOR_KEY, config(1)).expect("limiter constructs");
    assert!(matches!(
        limiter.check(Operation::Ping, b"192.0.2.1:1", 0),
        Ok(LimitDecision::Allowed { .. })
    ));
    assert_eq!(
        limiter.check(Operation::Ping, b"192.0.2.2:1", 4),
        Ok(LimitDecision::AtCapacity)
    );
    assert!(matches!(
        limiter.check(Operation::Ping, b"192.0.2.2:1", 10),
        Ok(LimitDecision::Allowed { .. })
    ));
    assert_eq!(limiter.snapshot().entry_count, 1);
}
