//! Pure operator-keyed, bounded mailbox-operation limiter.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
};

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
}

/// Inspectable limiter state containing only pseudonymous dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimiterSnapshot {
    /// Current number of `{operation, peer-key}` entries.
    pub entry_count: usize,
    /// Pseudonymous dimensions in stable order.
    pub dimensions: Vec<(Operation, PeerKey)>,
    /// Backwards clock observations clamped to the high-water mark.
    pub clock_reversals: u64,
    /// Least-recently-used dimensions removed at the hard cap.
    pub capacity_evictions: u64,
}

/// Limiter construction or clock error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LimiterError {
    /// A policy limit, window, cap, or sweep interval is zero.
    InvalidConfiguration,
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
    recency: u64,
}

/// One shared limiter across every mailbox operation.
pub struct Limiter {
    operator_key: [u8; 32],
    config: LimiterConfig,
    entries: BTreeMap<(Operation, PeerKey), Entry>,
    recency: BTreeSet<(u64, Operation, PeerKey)>,
    next_recency: u64,
    last_now: Option<u64>,
    last_sweep: Option<u64>,
    clock_reversals: u64,
    capacity_evictions: u64,
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
            recency: BTreeSet::new(),
            next_recency: 0,
            last_now: None,
            last_sweep: None,
            clock_reversals: 0,
            capacity_evictions: 0,
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
        let now = self.observe_time(now);
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
        if self.entries.contains_key(&dimension) {
            self.touch(dimension)?;
            let entry = self
                .entries
                .get_mut(&dimension)
                .expect("touched limiter dimension remains present");
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
            self.evict_lru();
        }
        let recency = self.take_recency()?;
        let mut attempts = VecDeque::new();
        attempts.push_back(now);
        self.entries.insert(
            dimension,
            Entry {
                attempts,
                cooldown_until: None,
                recency,
            },
        );
        self.recency.insert((recency, operation, peer_key));
        Ok(LimitDecision::Allowed {
            remaining: policy.limit - 1,
        })
    }

    /// Periodically remove inactive dimensions.
    pub fn sweep(&mut self, now: u64) -> Result<usize, LimiterError> {
        let now = self.observe_time(now);
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
            clock_reversals: self.clock_reversals,
            capacity_evictions: self.capacity_evictions,
        }
    }

    /// Return the current dimension count without allocating a snapshot.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Return the aggregate number of clamped backwards clock observations.
    #[must_use]
    pub const fn clock_reversals(&self) -> u64 {
        self.clock_reversals
    }

    pub(crate) fn sweep_if_due(&mut self, now: u64) -> Result<usize, LimiterError> {
        let now = self.observe_time(now);
        if self
            .last_sweep
            .is_some_and(|last| now.saturating_sub(last) < self.config.sweep_interval_seconds)
        {
            return Ok(0);
        }
        let removed = self.sweep_inner(now);
        self.last_sweep = Some(now);
        Ok(removed)
    }

    fn observe_time(&mut self, now: u64) -> u64 {
        let effective = self.last_now.map_or(now, |last| last.max(now));
        if effective != now {
            self.clock_reversals = self.clock_reversals.saturating_add(1);
        }
        self.last_now = Some(effective);
        effective
    }

    fn peer_key(&self, canonical_peer_address: &[u8]) -> PeerKey {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.operator_key)
            .expect("HMAC accepts every fixed-size key");
        mac.update(b"cbcl-pairing-peer/v1");
        match std::str::from_utf8(canonical_peer_address)
            .ok()
            .and_then(|address| address.parse::<IpAddr>().ok())
        {
            Some(IpAddr::V4(address)) => {
                mac.update(&[4]);
                mac.update(&address.octets());
            }
            Some(IpAddr::V6(address)) => {
                if let Some(address) = address.to_ipv4_mapped() {
                    mac.update(&[4]);
                    mac.update(&address.octets());
                } else {
                    mac.update(&[6]);
                    mac.update(&address.octets()[..8]);
                }
            }
            None => {
                mac.update(&[0]);
                mac.update(canonical_peer_address);
            }
        }
        PeerKey(mac.finalize().into_bytes().into())
    }

    fn take_recency(&mut self) -> Result<u64, LimiterError> {
        let recency = self.next_recency;
        self.next_recency = self
            .next_recency
            .checked_add(1)
            .ok_or(LimiterError::TimeOverflow)?;
        Ok(recency)
    }

    fn touch(&mut self, dimension: (Operation, PeerKey)) -> Result<(), LimiterError> {
        let previous = self
            .entries
            .get(&dimension)
            .expect("existing limiter dimension")
            .recency;
        self.recency.remove(&(previous, dimension.0, dimension.1));
        let recency = self.take_recency()?;
        self.entries
            .get_mut(&dimension)
            .expect("existing limiter dimension")
            .recency = recency;
        self.recency.insert((recency, dimension.0, dimension.1));
        Ok(())
    }

    fn evict_lru(&mut self) {
        let Some(victim) = self.recency.first().copied() else {
            return;
        };
        self.recency.remove(&victim);
        self.entries.remove(&(victim.1, victim.2));
        self.capacity_evictions = self.capacity_evictions.saturating_add(1);
    }

    fn sweep_inner(&mut self, now: u64) -> usize {
        let policies = self.config.policies;
        let removed: Vec<_> = self
            .entries
            .iter_mut()
            .filter_map(|(dimension, entry)| {
                if entry.cooldown_until.is_some_and(|retry_at| now >= retry_at) {
                    return Some((*dimension, entry.recency));
                }
                if entry.cooldown_until.is_some() {
                    return None;
                }
                prune_attempts(entry, policies[dimension.0.index()].window_seconds, now);
                entry
                    .attempts
                    .is_empty()
                    .then_some((*dimension, entry.recency))
            })
            .collect();
        for (dimension, recency) in &removed {
            self.entries.remove(dimension);
            self.recency.remove(&(*recency, dimension.0, dimension.1));
        }
        removed.len()
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
