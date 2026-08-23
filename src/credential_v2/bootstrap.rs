use super::checkpoint::{open_checkpoint_plaintext, seal_checkpoint_plaintext};
use super::{
    decode_carrier, decode_frame, encode_carrier, encode_frame, CredentialV2Carrier,
    CredentialV2CheckpointNonce, CredentialV2Context, CredentialV2Error, CredentialV2Frame,
    CredentialV2Presence, EndpointCheckpointV2, PendingCredentialV2Channel,
    SecureCredentialV2Channel,
};
use crate::{cpace, wire::Side};
use std::fmt;
use zeroize::Zeroizing;

const INNER_DOMAIN: &[u8] = b"cbcl-pairing allocator bootstrap/v2\0";
const MAX_INNER_BYTES: usize = 69_616;
const MAX_FRAME_BYTES: usize = 69_600;

/// Exact allocator state before the application reducer becomes active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2AllocatorBootstrapPhase {
    /// The protected mailbox exists and the separate claim token is live.
    Allocated,
    /// The relay admitted the claimant and the claim token was erased.
    Claimed,
    /// The allocator CPace share is the exact cached outbound frame.
    ShareSent,
    /// The allocator Finished value is the exact cached outbound frame.
    FinishedSent,
}

/// Relay membership and monitor projection retained across allocator crashes.
pub struct CredentialV2RelayState {
    pub(super) membership_token: Zeroizing<[u8; 32]>,
    pub(super) next_local_sequence: u8,
    pub(super) next_peer_sequence: u8,
    pub(super) awaiting_ack: bool,
    pub(super) cached_outbound: Option<CredentialV2Frame>,
}

impl CredentialV2RelayState {
    /// Start an allocated membership before any relay frame is queued.
    #[must_use]
    pub fn new(membership_token: [u8; 32]) -> Self {
        Self {
            membership_token: Zeroizing::new(membership_token),
            next_local_sequence: 0,
            next_peer_sequence: 0,
            awaiting_ack: false,
            cached_outbound: None,
        }
    }

    /// Borrow the relay bearer needed by the exact `open` command after recovery.
    #[must_use]
    pub fn membership_token(&self) -> &[u8; 32] {
        &self.membership_token
    }

    /// Borrow the exact sealed application frame awaiting relay acknowledgement.
    #[must_use]
    pub const fn cached_outbound_frame(&self) -> Option<&CredentialV2Frame> {
        self.cached_outbound.as_ref()
    }

    pub(super) fn cache_application_frame(
        &mut self,
        frame: CredentialV2Frame,
    ) -> Result<(), CredentialV2Error> {
        if self.awaiting_ack || !matches!(frame, CredentialV2Frame::Sealed { .. }) {
            return Err(CredentialV2Error::Phase);
        }
        self.cached_outbound = Some(frame);
        self.awaiting_ack = true;
        Ok(())
    }
}

impl fmt::Debug for CredentialV2RelayState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialV2RelayState")
            .field("membership_token", &"[REDACTED]")
            .field("next_local_sequence", &self.next_local_sequence)
            .field("next_peer_sequence", &self.next_peer_sequence)
            .field("awaiting_ack", &self.awaiting_ack)
            .field("cached_outbound", &self.cached_outbound.is_some())
            .finish()
    }
}

/// Crash-recoverable allocator state from carrier allocation through Finished.
pub struct CredentialV2AllocatorBootstrap {
    carrier: CredentialV2Carrier,
    presence: CredentialV2Presence,
    profile_digest: [u8; 32],
    relay: CredentialV2RelayState,
    phase: CredentialV2AllocatorBootstrapPhase,
    fresh_scalar: Option<Zeroizing<[u8; 32]>>,
    peer_cpace: Option<CredentialV2Frame>,
    pending: Option<PendingCredentialV2Channel>,
    cached_outbound: Option<CredentialV2Frame>,
    checkpoint_generation: u64,
    checkpoint_nonce: Option<[u8; 12]>,
}

impl fmt::Debug for CredentialV2AllocatorBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialV2AllocatorBootstrap")
            .field("phase", &self.phase)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl CredentialV2AllocatorBootstrap {
    /// Start from a relay-confirmed allocation and its separate presence values.
    pub fn new(
        carrier: CredentialV2Carrier,
        presence: CredentialV2Presence,
        profile_digest: [u8; 32],
        relay: CredentialV2RelayState,
    ) -> Result<Self, CredentialV2Error> {
        CredentialV2Context::derive(&carrier, profile_digest)?;
        Ok(Self {
            carrier,
            presence,
            profile_digest,
            relay,
            phase: CredentialV2AllocatorBootstrapPhase::Allocated,
            fresh_scalar: None,
            peer_cpace: None,
            pending: None,
            cached_outbound: None,
            checkpoint_generation: 0,
            checkpoint_nonce: None,
        })
    }

    /// Return the current exact bootstrap phase.
    #[must_use]
    pub const fn phase(&self) -> CredentialV2AllocatorBootstrapPhase {
        self.phase
    }

    /// Borrow the retained relay membership projection.
    #[must_use]
    pub const fn relay_state(&self) -> &CredentialV2RelayState {
        &self.relay
    }

    /// Borrow the exact frame that recovery must retransmit before any advance.
    #[must_use]
    pub const fn cached_outbound_frame(&self) -> Option<&CredentialV2Frame> {
        self.cached_outbound.as_ref()
    }

    /// Record authenticated relay admission and irreversibly erase claim token `T`.
    pub fn claimant_admitted(&mut self) -> Result<(), CredentialV2Error> {
        if self.phase != CredentialV2AllocatorBootstrapPhase::Allocated {
            return Err(CredentialV2Error::Phase);
        }
        let _ = self.presence.take_claim_token()?;
        self.phase = CredentialV2AllocatorBootstrapPhase::Claimed;
        Ok(())
    }

    /// Create and cache the allocator CPace share from caller CSPRNG scalar bytes.
    pub fn start_cpace(
        &mut self,
        fresh_scalar: [u8; 32],
    ) -> Result<CredentialV2Frame, CredentialV2Error> {
        if self.phase != CredentialV2AllocatorBootstrapPhase::Claimed {
            return Err(CredentialV2Error::Phase);
        }
        let context = CredentialV2Context::derive(&self.carrier, self.profile_digest)?;
        let (_, message) = context.start_cpace(Side::Allocator, &self.presence, fresh_scalar)?;
        let frame = CredentialV2Frame::cpace(&message)?;
        self.fresh_scalar = Some(Zeroizing::new(fresh_scalar));
        self.cached_outbound = Some(frame.clone());
        self.phase = CredentialV2AllocatorBootstrapPhase::ShareSent;
        Ok(frame)
    }

    /// Authenticate the claimant CPace share and cache the allocator Finished frame.
    pub fn receive_cpace(
        &mut self,
        peer_frame: &CredentialV2Frame,
    ) -> Result<CredentialV2Frame, CredentialV2Error> {
        if self.phase != CredentialV2AllocatorBootstrapPhase::ShareSent {
            return Err(CredentialV2Error::Phase);
        }
        let peer_message = peer_frame
            .cpace_message()
            .ok_or(CredentialV2Error::Schema)?;
        if peer_message.side != Side::Claimant {
            return Err(CredentialV2Error::Direction);
        }
        let scalar = self.fresh_scalar.as_ref().ok_or(CredentialV2Error::Phase)?;
        let context = CredentialV2Context::derive(&self.carrier, self.profile_digest)?;
        let (state, local_message) =
            context.start_cpace(Side::Allocator, &self.presence, **scalar)?;
        let local_frame = CredentialV2Frame::cpace(&local_message)?;
        if self.cached_outbound.as_ref() != Some(&local_frame) {
            return Err(CredentialV2Error::Profile);
        }
        let isk = cpace::finish(state, peer_message).map_err(|_| CredentialV2Error::Cpace)?;
        let pending = PendingCredentialV2Channel::new(
            Side::Allocator,
            isk,
            context.public_context(),
            &encode_frame(&local_frame)?,
            &encode_frame(peer_frame)?,
        )?;
        let finished = pending.local_finished_frame();
        self.peer_cpace = Some(peer_frame.clone());
        self.pending = Some(pending);
        self.cached_outbound = Some(finished.clone());
        self.phase = CredentialV2AllocatorBootstrapPhase::FinishedSent;
        Ok(finished)
    }

    /// Confirm the peer Finished value, dropping `C`, scalar, and pending schedule.
    pub fn confirm(
        mut self,
        peer_finished: &CredentialV2Frame,
    ) -> Result<(SecureCredentialV2Channel, CredentialV2RelayState), CredentialV2Error> {
        if self.phase != CredentialV2AllocatorBootstrapPhase::FinishedSent {
            return Err(CredentialV2Error::Phase);
        }
        let pending = self.pending.take().ok_or(CredentialV2Error::Phase)?;
        let channel = pending.confirm(peer_finished)?;
        self.cached_outbound = None;
        Ok((channel, self.relay))
    }

    /// Seal exact pre-Finished authority with mandatory numeric relay expiry.
    pub fn seal_checkpoint(
        &mut self,
        wrapping_key: &[u8; 32],
        generation: u64,
        nonce: CredentialV2CheckpointNonce,
        now: u64,
    ) -> Result<EndpointCheckpointV2, CredentialV2Error> {
        if now >= self.carrier.relay_expires_at() {
            return Err(CredentialV2Error::Expired);
        }
        let nonce = nonce.into_bytes();
        if generation == 0
            || generation != self.checkpoint_generation.saturating_add(1)
            || self.checkpoint_nonce == Some(nonce)
        {
            return Err(CredentialV2Error::Counter);
        }
        let plaintext = self.encode_inner(generation, nonce)?;
        let checkpoint = seal_checkpoint_plaintext(
            plaintext.as_slice(),
            Side::Allocator,
            &self.carrier,
            wrapping_key,
            generation,
            Some(self.carrier.relay_expires_at()),
            nonce,
        )?;
        self.checkpoint_generation = generation;
        self.checkpoint_nonce = Some(nonce);
        Ok(checkpoint)
    }

    /// Restore one exact allocator bootstrap state under caller-held bindings.
    pub fn restore_checkpoint(
        input: &[u8],
        wrapping_key: &[u8; 32],
        expected_carrier: &CredentialV2Carrier,
        expected_generation: u64,
        now: u64,
    ) -> Result<Self, CredentialV2Error> {
        let opened = open_checkpoint_plaintext(
            input,
            wrapping_key,
            Side::Allocator,
            expected_carrier,
            expected_generation,
            now,
        )?;
        if opened.expiry != Some(expected_carrier.relay_expires_at()) {
            return Err(CredentialV2Error::Schema);
        }
        Self::decode_inner(
            opened.plaintext.as_slice(),
            expected_carrier,
            expected_generation,
            opened.nonce,
        )
    }

    fn encode_inner(
        &self,
        generation: u64,
        nonce: [u8; 12],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialV2Error> {
        if !self.projection_is_consistent() {
            return Err(CredentialV2Error::Schema);
        }
        let carrier = encode_carrier(&self.carrier)?;
        let (cpace_secret, claim_token) = self.presence.checkpoint_parts();
        let mut output = Zeroizing::new(Vec::with_capacity(1024));
        output.extend_from_slice(INNER_DOMAIN);
        append_bytes(&mut output, &carrier)?;
        output.extend_from_slice(&self.profile_digest);
        output.push(phase_number(self.phase));
        output.extend_from_slice(cpace_secret);
        append_optional_fixed(
            &mut output,
            claim_token.map(|token| token.as_bytes().as_slice()),
        );
        output.extend_from_slice(self.relay.membership_token.as_slice());
        output.push(self.relay.next_local_sequence);
        output.push(self.relay.next_peer_sequence);
        output.push(u8::from(self.relay.awaiting_ack));
        append_optional_fixed(
            &mut output,
            self.fresh_scalar.as_ref().map(|value| value.as_slice()),
        );
        append_optional_frame(&mut output, self.peer_cpace.as_ref())?;
        append_optional_frame(&mut output, self.cached_outbound.as_ref())?;
        output.extend_from_slice(&generation.to_be_bytes());
        output.extend_from_slice(&nonce);
        if output.len() > MAX_INNER_BYTES {
            return Err(CredentialV2Error::Size);
        }
        Ok(output)
    }

    fn decode_inner(
        input: &[u8],
        expected_carrier: &CredentialV2Carrier,
        expected_generation: u64,
        expected_nonce: [u8; 12],
    ) -> Result<Self, CredentialV2Error> {
        let mut cursor = Cursor::new(input);
        if cursor.take(INNER_DOMAIN.len())? != INNER_DOMAIN {
            return Err(CredentialV2Error::Schema);
        }
        let carrier = decode_carrier(cursor.length_prefixed(MAX_INNER_BYTES)?)?;
        if &carrier != expected_carrier {
            return Err(CredentialV2Error::Profile);
        }
        let profile_digest = cursor.array()?;
        let phase = number_phase(cursor.byte()?)?;
        let cpace_secret = cursor.array()?;
        let claim_token = cursor.optional_array()?;
        let presence = CredentialV2Presence::from_checkpoint(cpace_secret, claim_token);
        let relay = CredentialV2RelayState {
            membership_token: Zeroizing::new(cursor.array()?),
            next_local_sequence: cursor.byte()?,
            next_peer_sequence: cursor.byte()?,
            awaiting_ack: cursor.boolean()?,
            cached_outbound: None,
        };
        let fresh_scalar = cursor.optional_array()?.map(Zeroizing::new);
        let peer_cpace = cursor.optional_frame()?;
        let cached_outbound = cursor.optional_frame()?;
        let generation = cursor.u64()?;
        let nonce = cursor.array()?;
        if !cursor.finished() || generation != expected_generation || nonce != expected_nonce {
            return Err(CredentialV2Error::Schema);
        }
        let mut bootstrap = Self {
            carrier,
            presence,
            profile_digest,
            relay,
            phase,
            fresh_scalar,
            peer_cpace,
            pending: None,
            cached_outbound,
            checkpoint_generation: generation,
            checkpoint_nonce: Some(nonce),
        };
        if !bootstrap.projection_is_consistent() {
            return Err(CredentialV2Error::Schema);
        }
        if phase == CredentialV2AllocatorBootstrapPhase::FinishedSent {
            bootstrap.rebuild_pending()?;
        }
        Ok(bootstrap)
    }

    fn rebuild_pending(&mut self) -> Result<(), CredentialV2Error> {
        let scalar = self
            .fresh_scalar
            .as_ref()
            .ok_or(CredentialV2Error::Schema)?;
        let peer = self.peer_cpace.as_ref().ok_or(CredentialV2Error::Schema)?;
        let peer_message = peer.cpace_message().ok_or(CredentialV2Error::Schema)?;
        let context = CredentialV2Context::derive(&self.carrier, self.profile_digest)?;
        let (state, local_message) =
            context.start_cpace(Side::Allocator, &self.presence, **scalar)?;
        let local = CredentialV2Frame::cpace(&local_message)?;
        let isk = cpace::finish(state, peer_message).map_err(|_| CredentialV2Error::Cpace)?;
        let pending = PendingCredentialV2Channel::new(
            Side::Allocator,
            isk,
            context.public_context(),
            &encode_frame(&local)?,
            &encode_frame(peer)?,
        )?;
        if self.cached_outbound.as_ref() != Some(&pending.local_finished_frame()) {
            return Err(CredentialV2Error::Profile);
        }
        self.pending = Some(pending);
        Ok(())
    }

    fn projection_is_consistent(&self) -> bool {
        let (_, claim) = self.presence.checkpoint_parts();
        match self.phase {
            CredentialV2AllocatorBootstrapPhase::Allocated => {
                claim.is_some()
                    && self.fresh_scalar.is_none()
                    && self.peer_cpace.is_none()
                    && self.pending.is_none()
                    && self.cached_outbound.is_none()
            }
            CredentialV2AllocatorBootstrapPhase::Claimed => {
                claim.is_none()
                    && self.fresh_scalar.is_none()
                    && self.peer_cpace.is_none()
                    && self.pending.is_none()
                    && self.cached_outbound.is_none()
            }
            CredentialV2AllocatorBootstrapPhase::ShareSent => {
                claim.is_none()
                    && self.fresh_scalar.is_some()
                    && self.peer_cpace.is_none()
                    && self.pending.is_none()
                    && self
                        .cached_outbound
                        .as_ref()
                        .and_then(CredentialV2Frame::cpace_message)
                        .is_some_and(|message| message.side == Side::Allocator)
            }
            CredentialV2AllocatorBootstrapPhase::FinishedSent => {
                claim.is_none()
                    && self.fresh_scalar.is_some()
                    && self
                        .peer_cpace
                        .as_ref()
                        .and_then(CredentialV2Frame::cpace_message)
                        .is_some_and(|message| message.side == Side::Claimant)
                    && self.cached_outbound.as_ref().is_some_and(|frame| {
                        matches!(
                            frame,
                            CredentialV2Frame::Finished {
                                side: Side::Allocator,
                                ..
                            }
                        )
                    })
            }
        }
    }
}

fn append_optional_fixed(output: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(value);
        }
        None => output.push(0),
    }
}

fn append_optional_frame(
    output: &mut Vec<u8>,
    frame: Option<&CredentialV2Frame>,
) -> Result<(), CredentialV2Error> {
    match frame {
        Some(frame) => {
            output.push(1);
            append_bytes(output, &encode_frame(frame)?)?;
        }
        None => output.push(0),
    }
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CredentialV2Error> {
    if value.is_empty() || value.len() > MAX_FRAME_BYTES {
        return Err(CredentialV2Error::Size);
    }
    let length = u32::try_from(value.len()).map_err(|_| CredentialV2Error::Size)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CredentialV2Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CredentialV2Error::Size)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(CredentialV2Error::Schema)?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, CredentialV2Error> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, CredentialV2Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CredentialV2Error::Schema),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CredentialV2Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| CredentialV2Error::Schema)
    }

    fn optional_array<const N: usize>(&mut self) -> Result<Option<[u8; N]>, CredentialV2Error> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.array()?)),
            _ => Err(CredentialV2Error::Schema),
        }
    }

    fn u64(&mut self) -> Result<u64, CredentialV2Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], CredentialV2Error> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| CredentialV2Error::Size)?;
        if length == 0 || length > maximum {
            return Err(CredentialV2Error::Size);
        }
        self.take(length)
    }

    fn optional_frame(&mut self) -> Result<Option<CredentialV2Frame>, CredentialV2Error> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(decode_frame(self.length_prefixed(MAX_FRAME_BYTES)?)?)),
            _ => Err(CredentialV2Error::Schema),
        }
    }

    fn finished(&self) -> bool {
        self.position == self.input.len()
    }
}

const fn phase_number(phase: CredentialV2AllocatorBootstrapPhase) -> u8 {
    match phase {
        CredentialV2AllocatorBootstrapPhase::Allocated => 0,
        CredentialV2AllocatorBootstrapPhase::Claimed => 1,
        CredentialV2AllocatorBootstrapPhase::ShareSent => 2,
        CredentialV2AllocatorBootstrapPhase::FinishedSent => 3,
    }
}

const fn number_phase(value: u8) -> Result<CredentialV2AllocatorBootstrapPhase, CredentialV2Error> {
    match value {
        0 => Ok(CredentialV2AllocatorBootstrapPhase::Allocated),
        1 => Ok(CredentialV2AllocatorBootstrapPhase::Claimed),
        2 => Ok(CredentialV2AllocatorBootstrapPhase::ShareSent),
        3 => Ok(CredentialV2AllocatorBootstrapPhase::FinishedSent),
        _ => Err(CredentialV2Error::Schema),
    }
}
