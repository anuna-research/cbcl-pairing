//! Reference in-memory relay service composed from the mailbox and limiter.

use crate::{
    limiter::{LimiterConfig, LimiterError},
    observability::{CapacityCaps, RelayMetrics},
    wire::{ClientMessage, ServerMessage},
};
use std::fmt;

/// Process-local identifier for one relay connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

/// Shell-supplied random values for commands that allocate identifiers or
/// membership tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayRandomness {
    /// Candidate random mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Candidate random membership token.
    pub membership_token: [u8; 32],
    /// Candidate numeric nameplate.
    pub nameplate: u32,
}

/// Bounded reference-relay configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    /// Private operator key used only for peer-address limiter HMACs.
    pub operator_key: [u8; 32],
    /// Shared limiter configuration.
    pub limiter: LimiterConfig,
    /// Hard observable resource caps.
    pub capacity: CapacityCaps,
    /// Whether new invitation allocation is enabled.
    pub allocation_enabled: bool,
}

/// One response routed to a live connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedMessage {
    /// Destination connection.
    pub connection: ConnectionId,
    /// Fully recognised response.
    pub message: ServerMessage,
}

/// Reference service error that cannot be represented as a normal wire reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// Temporary behavioural Red Gate sentinel.
    NotImplemented,
    /// Relay configuration is invalid.
    InvalidConfiguration,
    /// Time or limiter state failed.
    Limiter,
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RelayError {}

impl From<LimiterError> for RelayError {
    fn from(_: LimiterError) -> Self {
        Self::Limiter
    }
}

/// Application-unaware in-memory relay service.
pub struct RelayService;

impl RelayService {
    /// Construct a bounded service.
    pub fn new(_config: RelayConfig) -> Result<Self, RelayError> {
        Err(RelayError::NotImplemented)
    }

    /// Apply one fully recognised client command.
    pub fn handle(
        &mut self,
        _connection: ConnectionId,
        _canonical_peer_address: &[u8],
        _now: u64,
        _randomness: RelayRandomness,
        _message: ClientMessage,
    ) -> Result<Vec<RoutedMessage>, RelayError> {
        Err(RelayError::NotImplemented)
    }

    /// Remove one transport connection without closing its mailbox.
    pub fn disconnect(&mut self, _connection: ConnectionId) {}

    /// Reap mailboxes and limiter entries using explicit time.
    pub fn sweep(&mut self, _now: u64) -> Result<Vec<RoutedMessage>, RelayError> {
        Err(RelayError::NotImplemented)
    }

    /// Return the privacy-safe metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> Option<RelayMetrics> {
        None
    }
}
