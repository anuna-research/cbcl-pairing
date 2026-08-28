//! Pinned CPace255 conformance boundary.
//!
//! This module implements `CPACE-X25519-SHA512` from
//! `draft-irtf-cfrg-cpace-21`. Callers provide the entropy and protocol
//! context; this pure core owns neither a random-number generator nor I/O.

use crate::{
    context::PairingContext,
    wire::{Invitation, Side},
};
use sha2::{Digest, Sha512};
use std::fmt;
use subtle::ConstantTimeEq;
use x25519_dalek::x25519;
use zeroize::Zeroizing;

mod field;

use field::elligator2_curve25519;

const SHA512_INPUT_BLOCK_BYTES: usize = 128;

/// Exact pinned CPace draft revision.
pub const DRAFT_REVISION: u8 = 21;

/// Domain-separation input for the CPace255 generator.
pub const CPACE_DSI: &[u8] = b"CPace255";

/// Domain-separation input for the CPace255 intermediate session key.
pub const CPACE_ISK_DSI: &[u8] = b"CPace255_ISK";

pub use crate::wire::CpaceMessage;

/// A completed 64-byte CPace intermediate session key.
pub struct IntermediateSessionKey(Zeroizing<[u8; 64]>);

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
    scalar: Zeroizing<[u8; 32]>,
    local_message: CpaceMessage,
    sid: Vec<u8>,
    expected_peer_associated_data: Option<Vec<u8>>,
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
    /// A peer message claimed the same side as the receiver.
    SameSide,
    /// The peer point yielded the Curve25519 neutral element.
    InvalidPeerPoint,
    /// A combined encoding length overflowed the current platform.
    LengthOverflow,
    /// The SPEC-072 invitation context was invalid.
    InvalidContext,
    /// The peer did not carry its exact deterministic associated data.
    AssociatedData,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CpaceError {}

/// Build the exact `CPace255` generator string from PRS, CI, and session ID.
pub fn generator_string(
    prs: &[u8],
    channel_identifier: &[u8],
    session_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CpaceError> {
    let encoded_prefix_length = prepend_len_size(CPACE_DSI)?
        .checked_add(prepend_len_size(prs)?)
        .ok_or(CpaceError::LengthOverflow)?;
    let padding_length =
        SHA512_INPUT_BLOCK_BYTES.saturating_sub(encoded_prefix_length.saturating_add(1));
    let capacity = [
        prepend_len_size(CPACE_DSI)?,
        prepend_len_size(prs)?,
        leb128_size(padding_length)
            .checked_add(padding_length)
            .ok_or(CpaceError::LengthOverflow)?,
        prepend_len_size(channel_identifier)?,
        prepend_len_size(session_id)?,
    ]
    .into_iter()
    .try_fold(0_usize, |sum, length| sum.checked_add(length))
    .ok_or(CpaceError::LengthOverflow)?;

    let mut result = Vec::with_capacity(capacity);
    append_length_value(&mut result, CPACE_DSI);
    append_length_value(&mut result, prs);
    append_leb128(&mut result, padding_length);
    result.resize(result.len() + padding_length, 0);
    append_length_value(&mut result, channel_identifier);
    append_length_value(&mut result, session_id);
    Ok(Zeroizing::new(result))
}

/// Calculate the pinned CPace255 generator's encoded u-coordinate.
pub fn calculate_generator(
    prs: &[u8],
    channel_identifier: &[u8],
    session_id: &[u8],
) -> Result<[u8; 32], CpaceError> {
    let generator_input = generator_string(prs, channel_identifier, session_id)?;
    let digest = Sha512::digest(generator_input.as_slice());
    let mut field_element = [0_u8; 32];
    field_element.copy_from_slice(&digest[..32]);
    field_element[31] &= 0x7f;
    Ok(elligator2_curve25519(field_element))
}

/// Perform X25519 and reject the neutral element.
pub fn x25519_scalar_mult_vfy(scalar: [u8; 32], point: [u8; 32]) -> Result<[u8; 32], CpaceError> {
    let product = x25519(scalar, point);
    if bool::from(product.ct_eq(&[0_u8; 32])) {
        Err(CpaceError::InvalidPeerPoint)
    } else {
        Ok(product)
    }
}

/// Begin one side of CPace with a caller-supplied fresh 32-byte scalar.
pub fn start(
    side: Side,
    prs: &[u8],
    channel_identifier: &[u8],
    session_id: &[u8],
    associated_data: &[u8],
    fresh_scalar: [u8; 32],
) -> Result<(CpaceState, CpaceMessage), CpaceError> {
    let generator = calculate_generator(prs, channel_identifier, session_id)?;
    let share = x25519_scalar_mult_vfy(fresh_scalar, generator)?;
    let message = CpaceMessage {
        side,
        share,
        associated_data: associated_data.to_vec(),
    };
    let state = CpaceState {
        side,
        scalar: Zeroizing::new(fresh_scalar),
        local_message: message.clone(),
        sid: session_id.to_vec(),
        expected_peer_associated_data: None,
    };
    Ok((state, message))
}

/// Begin CPace with distinct local and expected peer associated data.
///
/// Versioned protocol profiles use this entry point when both role bindings
/// are derived from one authenticated public context.
pub fn start_bound(
    side: Side,
    prs: &[u8],
    channel_identifier: &[u8],
    session_id: &[u8],
    local_associated_data: &[u8],
    expected_peer_associated_data: &[u8],
    fresh_scalar: [u8; 32],
) -> Result<(CpaceState, CpaceMessage), CpaceError> {
    let (mut state, message) = start(
        side,
        prs,
        channel_identifier,
        session_id,
        local_associated_data,
        fresh_scalar,
    )?;
    state.expected_peer_associated_data = Some(expected_peer_associated_data.to_vec());
    Ok((state, message))
}

/// Begin CPace using only the normative SPEC-072 invitation context and a
/// caller-supplied fresh scalar.
pub fn start_pairing(
    side: Side,
    invitation: &Invitation,
    mailbox_id: [u8; 32],
    fresh_scalar: [u8; 32],
) -> Result<(CpaceState, CpaceMessage), CpaceError> {
    let context =
        PairingContext::derive(invitation, mailbox_id).map_err(|_| CpaceError::InvalidContext)?;
    let local_ad = context.associated_data(side);
    let peer_ad = context.associated_data(match side {
        Side::Allocator => Side::Claimant,
        Side::Claimant => Side::Allocator,
    });
    let (mut state, message) = start(
        side,
        &invitation.secret,
        context.channel_identifier(),
        context.session_id(),
        local_ad,
        fresh_scalar,
    )?;
    state.expected_peer_associated_data = Some(peer_ad.to_vec());
    Ok((state, message))
}

/// Complete CPace, consuming the local state and validating the peer share.
pub fn finish(
    state: CpaceState,
    peer_message: &CpaceMessage,
) -> Result<IntermediateSessionKey, CpaceError> {
    if state.side == peer_message.side {
        return Err(CpaceError::SameSide);
    }
    if state
        .expected_peer_associated_data
        .as_ref()
        .is_some_and(|expected| expected != &peer_message.associated_data)
    {
        return Err(CpaceError::AssociatedData);
    }

    let shared_point = Zeroizing::new(x25519_scalar_mult_vfy(*state.scalar, peer_message.share)?);
    let (allocator, claimant) = match state.side {
        Side::Allocator => (&state.local_message, peer_message),
        Side::Claimant => (peer_message, &state.local_message),
    };

    let mut key_input = Zeroizing::new(Vec::new());
    append_length_value(&mut key_input, CPACE_ISK_DSI);
    append_length_value(&mut key_input, &state.sid);
    append_length_value(&mut key_input, shared_point.as_slice());
    append_length_value(&mut key_input, &allocator.share);
    append_length_value(&mut key_input, &allocator.associated_data);
    append_length_value(&mut key_input, &claimant.share);
    append_length_value(&mut key_input, &claimant.associated_data);

    Ok(IntermediateSessionKey(Zeroizing::new(
        Sha512::digest(key_input.as_slice()).into(),
    )))
}

fn prepend_len_size(value: &[u8]) -> Result<usize, CpaceError> {
    leb128_size(value.len())
        .checked_add(value.len())
        .ok_or(CpaceError::LengthOverflow)
}

fn leb128_size(mut value: usize) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        size += 1;
        value >>= 7;
    }
    size
}

fn append_leb128(output: &mut Vec<u8>, mut value: usize) {
    loop {
        let low_bits = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            output.push(low_bits);
            return;
        }
        output.push(low_bits | 0x80);
    }
}

fn append_length_value(output: &mut Vec<u8>, value: &[u8]) {
    append_leb128(output, value.len());
    output.extend_from_slice(value);
}
