//! SPEC-072 transcript, key-confirmation, and directional AEAD channel.

use crate::{
    cpace::IntermediateSessionKey,
    wire::{ChannelFrame, Direction, Side},
};
use std::fmt;

/// Largest plaintext accepted by the generic sealed-frame transport.
pub const MAX_SEALED_PLAINTEXT: usize = 69_556;

/// Secure-channel validation or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// The secure channel has not yet been implemented.
    NotImplemented,
    /// The peer's role-bound Finished value did not verify.
    FinishedMismatch,
    /// The frame travels in the wrong direction for this endpoint.
    DirectionMismatch,
    /// The frame counter is not the exact next expected value.
    CounterMismatch,
    /// AES-GCM authentication failed.
    InvalidTag,
    /// The plaintext or ciphertext falls outside its fixed bound.
    MessageSize,
    /// The directional counter space has been exhausted.
    CounterExhausted,
    /// A prior peer or cryptographic failure made the channel terminal.
    Terminal,
    /// A non-sealed frame reached application transport.
    UnexpectedFrame,
    /// Deterministic CBOR encoding failed.
    Encoding,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ChannelError {}

/// Derived channel awaiting verification of the peer's Finished value.
pub struct PendingChannel;

impl fmt::Debug for PendingChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingChannel([REDACTED])")
    }
}

impl PendingChannel {
    /// Derive the complete role-bound channel schedule from CPace ISK and the
    /// three exact transcript encodings.
    pub fn new(
        _local_side: Side,
        _isk: IntermediateSessionKey,
        _public_context: &[u8],
        _allocator_cpace_frame: &[u8],
        _claimant_cpace_frame: &[u8],
    ) -> Result<Self, ChannelError> {
        Err(ChannelError::NotImplemented)
    }

    /// Return this endpoint's public role-bound Finished value.
    #[must_use]
    pub fn local_finished(&self) -> [u8; 64] {
        [0; 64]
    }

    /// Return the exact transcript hash.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 64] {
        [0; 64]
    }

    /// Verify the peer's Finished value and activate application transport.
    pub fn confirm(self, _peer_finished: &[u8]) -> Result<SecureChannel, ChannelError> {
        Err(ChannelError::NotImplemented)
    }
}

/// Confirmed, role-directed, contiguous-counter application channel.
pub struct SecureChannel;

impl fmt::Debug for SecureChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureChannel([REDACTED])")
    }
}

impl SecureChannel {
    /// Seal one plaintext with the exact next local-direction counter.
    pub fn seal(&mut self, _plaintext: &[u8]) -> Result<ChannelFrame, ChannelError> {
        Err(ChannelError::NotImplemented)
    }

    /// Open one exact-next peer-direction sealed frame.
    pub fn open(&mut self, _frame: &ChannelFrame) -> Result<Vec<u8>, ChannelError> {
        Err(ChannelError::NotImplemented)
    }

    /// Return the application exporter secret.
    #[must_use]
    pub fn exporter(&self) -> &[u8; 32] {
        &[0; 32]
    }

    /// Return the transcript hash bound to this channel.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 64] {
        [0; 64]
    }
}

/// XOR one direction IV with the big-endian 96-bit encoding of `counter`.
#[must_use]
pub fn derive_nonce(_iv: [u8; 12], _counter: u64) -> [u8; 12] {
    [0; 12]
}

/// Encode exact deterministic CBOR additional data for one sealed frame.
pub fn sealed_aad(
    _direction: Direction,
    _counter: u64,
    _transcript_hash: &[u8; 64],
) -> Result<Vec<u8>, ChannelError> {
    Err(ChannelError::NotImplemented)
}
