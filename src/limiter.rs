//! Pure operator-keyed, bounded mailbox-operation limiter.

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
}

impl std::fmt::Display for LimiterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LimiterError {}

/// One shared limiter across every mailbox operation.
#[derive(Debug)]
pub struct Limiter {
    _private: (),
}

impl Limiter {
    /// Create a limiter using a private operator key.
    pub fn new(_operator_key: [u8; 32], _config: LimiterConfig) -> Result<Self, LimiterError> {
        Err(LimiterError::NotImplemented)
    }

    /// Check and record one operation for canonical peer-address bytes.
    pub fn check(
        &mut self,
        _operation: Operation,
        _canonical_peer_address: &[u8],
        _now: u64,
    ) -> Result<LimitDecision, LimiterError> {
        Err(LimiterError::NotImplemented)
    }

    /// Periodically remove inactive dimensions.
    pub fn sweep(&mut self, _now: u64) -> Result<usize, LimiterError> {
        Err(LimiterError::NotImplemented)
    }

    /// Return pseudonymous bounded state for gauges and conformance tests.
    #[must_use]
    pub fn snapshot(&self) -> LimiterSnapshot {
        LimiterSnapshot {
            entry_count: 0,
            dimensions: Vec::new(),
        }
    }
}
