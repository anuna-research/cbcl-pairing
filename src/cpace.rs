//! Pinned CPace255 conformance boundary.
//!
//! This module implements `CPACE-X25519-SHA512` from
//! `draft-irtf-cfrg-cpace-21`. Callers provide the entropy and protocol
//! context; this pure core owns neither a random-number generator nor I/O.

use crate::wire::Side;
use std::fmt;

/// Exact pinned CPace draft revision.
pub const DRAFT_REVISION: u8 = 21;

/// Domain-separation input for the CPace255 generator.
pub const CPACE_DSI: &[u8] = b"CPace255";

/// Domain-separation input for the CPace255 intermediate session key.
pub const CPACE_ISK_DSI: &[u8] = b"CPace255_ISK";

/// One party's CPace share and associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpaceMessage {
    /// The protocol side which emitted this message.
    pub side: Side,
    /// Encoded Curve25519 Montgomery u-coordinate.
    pub share: [u8; 32],
    /// Side-specific associated data bound into the transcript.
    pub associated_data: Vec<u8>,
}

/// A completed 64-byte CPace intermediate session key.
#[derive(Clone, Eq, PartialEq)]
pub struct IntermediateSessionKey([u8; 64]);

impl IntermediateSessionKey {
    /// Borrow the exact 64 key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for IntermediateSessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IntermediateSessionKey([REDACTED])")
    }
}

/// Consumed local CPace state between share generation and completion.
pub struct CpaceState {
    side: Side,
    scalar: [u8; 32],
    local_message: CpaceMessage,
    sid: Vec<u8>,
}

impl fmt::Debug for CpaceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CpaceState")
            .field("side", &self.side)
            .field("scalar", &"[REDACTED]")
            .field("local_message", &self.local_message)
            .field("sid", &self.sid)
            .finish()
    }
}

/// CPace input or peer-validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpaceError {
    /// The pinned construction has not yet been implemented.
    NotImplemented,
    /// A peer message claimed the same side as the receiver.
    SameSide,
    /// The peer point yielded the Curve25519 neutral element.
    InvalidPeerPoint,
    /// A length could not be represented by the draft's length encoding.
    LengthOverflow,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CpaceError {}

/// Build the exact `CPace255` generator string from PRS, CI, and session ID.
pub fn generator_string(
    _prs: &[u8],
    _channel_identifier: &[u8],
    _session_id: &[u8],
) -> Result<Vec<u8>, CpaceError> {
    Err(CpaceError::NotImplemented)
}

/// Calculate the pinned CPace255 generator's encoded u-coordinate.
pub fn calculate_generator(
    _prs: &[u8],
    _channel_identifier: &[u8],
    _session_id: &[u8],
) -> Result<[u8; 32], CpaceError> {
    Err(CpaceError::NotImplemented)
}

/// Perform X25519 and reject the neutral element.
pub fn x25519_scalar_mult_vfy(_scalar: [u8; 32], _point: [u8; 32]) -> Result<[u8; 32], CpaceError> {
    Err(CpaceError::NotImplemented)
}

/// Begin one side of CPace with a caller-supplied fresh 32-byte scalar.
pub fn start(
    _side: Side,
    _prs: &[u8],
    _channel_identifier: &[u8],
    _session_id: &[u8],
    _associated_data: &[u8],
    _fresh_scalar: [u8; 32],
) -> Result<(CpaceState, CpaceMessage), CpaceError> {
    Err(CpaceError::NotImplemented)
}

/// Complete CPace, consuming the local state and validating the peer share.
pub fn finish(
    _state: CpaceState,
    _peer_message: &CpaceMessage,
) -> Result<IntermediateSessionKey, CpaceError> {
    Err(CpaceError::NotImplemented)
}
