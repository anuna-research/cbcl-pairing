//! Pure operator-keyed, bounded mailbox-operation limiter.

use std::collections::{BTreeMap, VecDeque};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Mandatory cooldown after an operation budget is exceeded.
pub const COOLDOWN_SECONDS: u64 = 300;

/// Closed mailbox-operation dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    /// Version bind.
    Bind,
    /// Mailbox allocation.
    Allocate,
    /// Locator claim.
    Claim,
    /// Membership open.
    Open,
    /// Opaque frame put.
    Put,
    /// Peer-frame acknowledgement.
    Ack,
    /// Explicit close.
    Close,
    /// Liveness ping.
    Ping,
}

impl Operation {
    /// Every operation in stable metric order.
    pub const ALL: [Self; 8] = [
        Self::Bind,
        Self::Allocate,
        Self::Claim,
        Self::Open,
        Self::Put,
        Self::Ack,
        Self::Close,
        Self::Ping,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Bind => 0,
            Self::Allocate => 1,
            Self::Claim => 2,
            Self::Open => 3,
            Self::Put => 4,
            Self::Ack => 5,
            Self::Close => 6,
            Self::Ping => 7,
        }
    }
}

/// Opaque operator-keyed HMAC of one canonical peer address.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    /// Return the pseudonymous key octets for conformance inspection.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for PeerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PeerKey(REDACTED)")
    }
}

/// Sliding-window policy for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationPolicy {
    /// Maximum accepted attempts in the window.
    pub limit: u32,
    /// Sliding-window width in seconds.
    pub window_seconds: u64,
}

/// Complete bounded limiter configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimiterConfig {
    policies: [OperationPolicy; 8],
    entry_cap: usize,
    sweep_interval_seconds: u64,
}

impl LimiterConfig {
    /// Build a configuration using one default policy for all operations.
    #[must_use]
    pub const fn new(
        default_policy: OperationPolicy,
        entry_cap: usize,
        sweep_interval_seconds: u64,
    ) -> Self {
        Self {
            policies: [default_policy; 8],
            entry_cap,
            sweep_interval_seconds,
        }
    }

    /// Replace the policy for one operation.
    #[must_use]
    pub const fn with_policy(mut self, operation: Operation, policy: OperationPolicy) -> Self {
        self.policies[operation.index()] = policy;
        self
    }

    /// Return the hard dimension-entry cap.
    #[must_use]
    pub const fn entry_cap(&self) -> usize {
        self.entry_cap
    }
}

/// One admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitDecision {
    /// This attempt may proceed.
    Allowed {
        /// Attempts still available in the current window.
        remaining: u32,
    },
    /// The peer-operation dimension is cooling down.
    Cooldown {
        /// Absolute second at which admission may resume.
        retry_at: u64,
    },
    /// A new dimension was refused at the configured hard cap.
    AtCapacity,
}

/// Inspectable limiter state containing only pseudonymous dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimiterSnapshot {
    /// Current number of `{operation, peer-key}` entries.
    pub entry_count: usize,
    /// Pseudonymous dimensions in stable order.
    pub dimensions: Vec<(Operation, PeerKey)>,
}

/// Limiter construction or clock error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LimiterError {
    /// Behavioural stub used by the detailed Red Gate.
    NotImplemented,
    /// A policy limit, window, cap, or sweep interval is zero.
    InvalidConfiguration,
    /// Supplied time moved backwards.
    TimeReversal,
    /// Cooldown expiry overflowed absolute time.
    TimeOverflow,
    /// Canonical peer address input was empty.
    EmptyPeerAddress,
}

impl std::fmt::Display for LimiterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LimiterError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    attempts: VecDeque<u64>,
    cooldown_until: Option<u64>,
}

/// One shared limiter across every mailbox operation.
pub struct Limiter {
    operator_key: [u8; 32],
    config: LimiterConfig,
    entries: BTreeMap<(Operation, PeerKey), Entry>,
    last_now: Option<u64>,
    last_sweep: Option<u64>,
}

impl std::fmt::Debug for Limiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Limiter")
            .field("operator_key", &"REDACTED")
            .field("config", &self.config)
            .field("snapshot", &self.snapshot())
            .field("last_now", &self.last_now)
            .field("last_sweep", &self.last_sweep)
            .finish()
    }
}

impl Limiter {
    /// Create a limiter using a private operator key.
    pub fn new(operator_key: [u8; 32], config: LimiterConfig) -> Result<Self, LimiterError> {
        if config.entry_cap == 0
            || config.sweep_interval_seconds == 0
            || config
                .policies
                .iter()
                .any(|policy| policy.limit == 0 || policy.window_seconds == 0)
        {
            return Err(LimiterError::InvalidConfiguration);
        }
        Ok(Self {
            operator_key,
            config,
            entries: BTreeMap::new(),
            last_now: None,
            last_sweep: None,
        })
    }

    /// Check and record one operation for canonical peer-address bytes.
    pub fn check(
        &mut self,
        operation: Operation,
        canonical_peer_address: &[u8],
        now: u64,
    ) -> Result<LimitDecision, LimiterError> {
        if canonical_peer_address.is_empty() {
            return Err(LimiterError::EmptyPeerAddress);
        }
        self.observe_time(now)?;
        if self
            .last_sweep
            .is_none_or(|last| now.saturating_sub(last) >= self.config.sweep_interval_seconds)
        {
            self.sweep_inner(now);
            self.last_sweep = Some(now);
        }

        let peer_key = self.peer_key(canonical_peer_address);
        let dimension = (operation, peer_key);
        let policy = self.config.policies[operation.index()];
        if let Some(entry) = self.entries.get_mut(&dimension) {
            if let Some(retry_at) = entry.cooldown_until {
                if now < retry_at {
                    return Ok(LimitDecision::Cooldown { retry_at });
                }
                entry.cooldown_until = None;
                entry.attempts.clear();
            }
            prune_attempts(entry, policy.window_seconds, now);
            if entry.attempts.len() >= policy.limit as usize {
                let retry_at = now
                    .checked_add(COOLDOWN_SECONDS)
                    .ok_or(LimiterError::TimeOverflow)?;
                entry.cooldown_until = Some(retry_at);
                return Ok(LimitDecision::Cooldown { retry_at });
            }
            entry.attempts.push_back(now);
            return Ok(LimitDecision::Allowed {
                remaining: policy.limit - entry.attempts.len() as u32,
            });
        }

        if self.entries.len() >= self.config.entry_cap {
            return Ok(LimitDecision::AtCapacity);
        }
        let mut attempts = VecDeque::new();
        attempts.push_back(now);
        self.entries.insert(
            dimension,
            Entry {
                attempts,
                cooldown_until: None,
            },
        );
        Ok(LimitDecision::Allowed {
            remaining: policy.limit - 1,
        })
    }

    /// Periodically remove inactive dimensions.
    pub fn sweep(&mut self, now: u64) -> Result<usize, LimiterError> {
        self.observe_time(now)?;
        let removed = self.sweep_inner(now);
        self.last_sweep = Some(now);
        Ok(removed)
    }

    /// Return pseudonymous bounded state for gauges and conformance tests.
    #[must_use]
    pub fn snapshot(&self) -> LimiterSnapshot {
        LimiterSnapshot {
            entry_count: self.entries.len(),
            dimensions: self.entries.keys().copied().collect(),
        }
    }

    fn observe_time(&mut self, now: u64) -> Result<(), LimiterError> {
        if self.last_now.is_some_and(|last| now < last) {
            return Err(LimiterError::TimeReversal);
        }
        self.last_now = Some(now);
        Ok(())
    }

    fn peer_key(&self, canonical_peer_address: &[u8]) -> PeerKey {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.operator_key)
            .expect("HMAC accepts every fixed-size key");
        mac.update(canonical_peer_address);
        PeerKey(mac.finalize().into_bytes().into())
    }

    fn sweep_inner(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        let policies = self.config.policies;
        self.entries.retain(|(operation, _), entry| {
            if entry.cooldown_until.is_some_and(|retry_at| now >= retry_at) {
                return false;
            }
            if entry.cooldown_until.is_some() {
                return true;
            }
            prune_attempts(entry, policies[operation.index()].window_seconds, now);
            !entry.attempts.is_empty()
        });
        before - self.entries.len()
    }
}

fn prune_attempts(entry: &mut Entry, window_seconds: u64, now: u64) {
    while entry
        .attempts
        .front()
        .is_some_and(|timestamp| now.saturating_sub(*timestamp) >= window_seconds)
    {
        entry.attempts.pop_front();
    }
}
