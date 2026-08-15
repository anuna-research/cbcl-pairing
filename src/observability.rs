//! Closed, privacy-safe relay logging and metric dimensions.

use crate::limiter::Operation;

/// Closed normalised relay outcome dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelayOutcome {
    /// Recognised operation succeeded.
    Success,
    /// Input or state was invalid.
    Invalid,
    /// Locator or membership was absent.
    NotFound,
    /// Immutable sequence conflict or gap.
    Conflict,
    /// Explicit terminal closure.
    Closed,
    /// Third membership crowded a mailbox.
    Crowded,
    /// Original expiry elapsed.
    Expired,
    /// Input exceeded a size bound.
    TooLarge,
    /// Limiter refused the operation.
    RateLimited,
    /// Bounded relay resources were unavailable.
    Unavailable,
}

impl RelayOutcome {
    /// Every outcome in stable metric order.
    pub const ALL: [Self; 10] = [
        Self::Success,
        Self::Invalid,
        Self::NotFound,
        Self::Conflict,
        Self::Closed,
        Self::Crowded,
        Self::Expired,
        Self::TooLarge,
        Self::RateLimited,
        Self::Unavailable,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::Invalid => 1,
            Self::NotFound => 2,
            Self::Conflict => 3,
            Self::Closed => 4,
            Self::Crowded => 5,
            Self::Expired => 6,
            Self::TooLarge => 7,
            Self::RateLimited => 8,
            Self::Unavailable => 9,
        }
    }
}

/// One safe diagnostic event for the effectful logger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLogEvent {
    /// Closed operation label.
    pub operation: Operation,
    /// Closed normalised outcome label.
    pub outcome: RelayOutcome,
}

/// One counter sample for `pairing_mailbox_operations_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationMetric {
    /// Closed operation label.
    pub operation: Operation,
    /// Closed normalised outcome label.
    pub outcome: RelayOutcome,
    /// Monotonic count.
    pub count: u64,
}

/// Configured hard caps used by bounded-state alerts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityCaps {
    /// Maximum open mailboxes.
    pub open_mailboxes: u64,
    /// Maximum queued opaque bytes.
    pub queue_bytes: u64,
    /// Maximum limiter entries.
    pub limiter_entries: u64,
}

/// Current aggregate bounded-state gauges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayGauges {
    /// `pairing_mailbox_open`.
    pub open_mailboxes: u64,
    /// `pairing_mailbox_queue_bytes`.
    pub queue_bytes: u64,
    /// `pairing_mailbox_limiter_entries`.
    pub limiter_entries: u64,
}

/// Closed alerts that fire at 80 percent of configured caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityAlerts {
    /// Open-mailbox gauge reached its threshold.
    pub open_mailboxes: bool,
    /// Queue-byte gauge reached its threshold.
    pub queue_bytes: bool,
    /// Limiter-entry gauge reached its threshold.
    pub limiter_entries: bool,
}

/// Snapshot of all safe relay metrics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayMetrics {
    /// Non-zero closed-dimension operation counters.
    pub operations: Vec<OperationMetric>,
    /// Current aggregate gauges.
    pub gauges: RelayGauges,
    /// Current 80-percent cap alerts.
    pub alerts: CapacityAlerts,
}

/// Bounded in-process metric accumulator with no dynamic labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayObservability {
    caps: CapacityCaps,
    counters: [[u64; 10]; 8],
    gauges: RelayGauges,
}

impl RelayObservability {
    /// Create an accumulator for configured resource caps.
    #[must_use]
    pub const fn new(caps: CapacityCaps) -> Self {
        Self {
            caps,
            counters: [[0; 10]; 8],
            gauges: RelayGauges {
                open_mailboxes: 0,
                queue_bytes: 0,
                limiter_entries: 0,
            },
        }
    }

    /// Record one recognised operation and return its safe log event.
    pub fn record(&mut self, _operation: Operation, _outcome: RelayOutcome) -> RelayLogEvent {
        panic!("limiter-observability Red Gate")
    }

    /// Replace aggregate gauges from current bounded relay state.
    pub fn set_gauges(&mut self, _gauges: RelayGauges) {
        panic!("limiter-observability Red Gate")
    }

    /// Return counters, gauges, and threshold alerts.
    #[must_use]
    pub fn metrics(&self) -> RelayMetrics {
        panic!("limiter-observability Red Gate")
    }
}
