//! SPEC-072 transcript, key-confirmation, and directional AEAD channel.

use crate::{
    context::PairingContext,
    cpace::IntermediateSessionKey,
    wire::{ChannelFrame, Direction, Invitation, Side},
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Largest plaintext accepted by the generic sealed-frame transport.
pub const MAX_SEALED_PLAINTEXT: usize = 69_556;

/// Secure-channel validation or lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
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
    /// The fixed-size HKDF or HMAC schedule failed.
    KeySchedule,
    /// Local authenticated encryption failed after validation.
    Encryption,
    /// The invitation and resolved mailbox could not form the normative
    /// SPEC-072 public context.
    InvalidContext,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ChannelError {}

/// Derived channel awaiting verification of the peer's Finished value.
pub struct PendingChannel {
    local_side: Side,
    transcript_hash: [u8; 64],
    local_finished: [u8; 64],
    peer_finished: [u8; 64],
    secrets: PendingSecrets,
}

struct PendingSecrets {
    key_allocator_to_claimant: Zeroizing<[u8; 32]>,
    key_claimant_to_allocator: Zeroizing<[u8; 32]>,
    iv_allocator_to_claimant: Zeroizing<[u8; 12]>,
    iv_claimant_to_allocator: Zeroizing<[u8; 12]>,
    exporter: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PendingChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingChannel([REDACTED])")
    }
}

impl PendingChannel {
    /// Derive the normative SPEC-072 channel schedule without allowing the
    /// application to invent a public-context encoding.
    pub fn new_pairing(
        local_side: Side,
        isk: IntermediateSessionKey,
        invitation: &Invitation,
        mailbox_id: [u8; 32],
        allocator_cpace_frame: &[u8],
        claimant_cpace_frame: &[u8],
    ) -> Result<Self, ChannelError> {
        let context = PairingContext::derive(invitation, mailbox_id)
            .map_err(|_| ChannelError::InvalidContext)?;
        Self::new(
            local_side,
            isk,
            context.channel_context(),
            allocator_cpace_frame,
            claimant_cpace_frame,
        )
    }

    /// Derive the complete role-bound channel schedule from CPace ISK and the
    /// three exact transcript encodings.
    pub fn new(
        local_side: Side,
        isk: IntermediateSessionKey,
        public_context: &[u8],
        allocator_cpace_frame: &[u8],
        claimant_cpace_frame: &[u8],
    ) -> Result<Self, ChannelError> {
        let transcript_hash =
            calculate_transcript_hash(public_context, allocator_cpace_frame, claimant_cpace_frame)?;
        let hkdf = Hkdf::<Sha512>::new(Some(&[]), isk.as_bytes());
        let kc_allocator = expand::<32>(&hkdf, b"pairing-v1 kc A", &transcript_hash)?;
        let kc_claimant = expand::<32>(&hkdf, b"pairing-v1 kc B", &transcript_hash)?;
        let allocator_finished =
            finished(&kc_allocator, b"pairing-v1 finished A", &transcript_hash)?;
        let claimant_finished = finished(&kc_claimant, b"pairing-v1 finished B", &transcript_hash)?;
        let secrets = PendingSecrets {
            key_allocator_to_claimant: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-v1 key A-B",
                &transcript_hash,
            )?),
            key_claimant_to_allocator: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-v1 key B-A",
                &transcript_hash,
            )?),
            iv_allocator_to_claimant: Zeroizing::new(expand::<12>(
                &hkdf,
                b"pairing-v1 iv A-B",
                &transcript_hash,
            )?),
            iv_claimant_to_allocator: Zeroizing::new(expand::<12>(
                &hkdf,
                b"pairing-v1 iv B-A",
                &transcript_hash,
            )?),
            exporter: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-v1 exporter",
                &transcript_hash,
            )?),
        };
        let (local_finished, peer_finished) = match local_side {
            Side::Allocator => (allocator_finished, claimant_finished),
            Side::Claimant => (claimant_finished, allocator_finished),
        };
        Ok(Self {
            local_side,
            transcript_hash,
            local_finished,
            peer_finished,
            secrets,
        })
    }

    /// Return this endpoint's public role-bound Finished value.
    #[must_use]
    pub fn local_finished(&self) -> [u8; 64] {
        self.local_finished
    }

    /// Return the exact transcript hash.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 64] {
        self.transcript_hash
    }

    /// Verify the peer's Finished value and activate application transport.
    pub fn confirm(self, peer_finished: &[u8]) -> Result<SecureChannel, ChannelError> {
        if peer_finished.len() != 64
            || !bool::from(self.peer_finished.as_slice().ct_eq(peer_finished))
        {
            return Err(ChannelError::FinishedMismatch);
        }

        let (send_key, receive_key, send_iv, receive_iv) = match self.local_side {
            Side::Allocator => (
                self.secrets.key_allocator_to_claimant,
                self.secrets.key_claimant_to_allocator,
                self.secrets.iv_allocator_to_claimant,
                self.secrets.iv_claimant_to_allocator,
            ),
            Side::Claimant => (
                self.secrets.key_claimant_to_allocator,
                self.secrets.key_allocator_to_claimant,
                self.secrets.iv_claimant_to_allocator,
                self.secrets.iv_allocator_to_claimant,
            ),
        };
        Ok(SecureChannel {
            local_side: self.local_side,
            transcript_hash: self.transcript_hash,
            send_key,
            receive_key,
            send_iv,
            receive_iv,
            exporter: self.secrets.exporter,
            next_send_counter: Some(0),
            next_receive_counter: Some(0),
            terminal: false,
        })
    }
}

/// Confirmed, role-directed, contiguous-counter application channel.
pub struct SecureChannel {
    local_side: Side,
    transcript_hash: [u8; 64],
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_iv: Zeroizing<[u8; 12]>,
    receive_iv: Zeroizing<[u8; 12]>,
    exporter: Zeroizing<[u8; 32]>,
    next_send_counter: Option<u64>,
    next_receive_counter: Option<u64>,
    terminal: bool,
}

impl fmt::Debug for SecureChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureChannel([REDACTED])")
    }
}

impl SecureChannel {
    /// Seal one plaintext with the exact next local-direction counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<ChannelFrame, ChannelError> {
        if self.terminal {
            return Err(ChannelError::Terminal);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_SEALED_PLAINTEXT {
            return Err(ChannelError::MessageSize);
        }
        let counter = self
            .next_send_counter
            .ok_or(ChannelError::CounterExhausted)?;
        let direction = send_direction(self.local_side);
        let aad = sealed_aad(direction, counter, &self.transcript_hash)?;
        let nonce_bytes = derive_nonce(*self.send_iv, counter);
        let nonce = nonce_bytes.into();
        let cipher = Aes256Gcm::new_from_slice(self.send_key.as_slice())
            .map_err(|_| ChannelError::Encryption)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ChannelError::Encryption)?;
        self.next_send_counter = counter.checked_add(1);
        Ok(ChannelFrame::Sealed {
            direction,
            counter,
            ciphertext,
        })
    }

    /// Open one exact-next peer-direction sealed frame.
    pub fn open(&mut self, frame: &ChannelFrame) -> Result<Vec<u8>, ChannelError> {
        if self.terminal {
            return Err(ChannelError::Terminal);
        }
        let ChannelFrame::Sealed {
            direction,
            counter,
            ciphertext,
        } = frame
        else {
            return self.fail(ChannelError::UnexpectedFrame);
        };
        if *direction != receive_direction(self.local_side) {
            return self.fail(ChannelError::DirectionMismatch);
        }
        let Some(expected_counter) = self.next_receive_counter else {
            return self.fail(ChannelError::CounterExhausted);
        };
        if *counter != expected_counter {
            return self.fail(ChannelError::CounterMismatch);
        }
        if !(17..=MAX_SEALED_PLAINTEXT + 16).contains(&ciphertext.len()) {
            return self.fail(ChannelError::MessageSize);
        }

        let aad = sealed_aad(*direction, *counter, &self.transcript_hash)?;
        let nonce_bytes = derive_nonce(*self.receive_iv, *counter);
        let nonce = nonce_bytes.into();
        let cipher = Aes256Gcm::new_from_slice(self.receive_key.as_slice())
            .map_err(|_| ChannelError::Encryption)?;
        let plaintext = match cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return self.fail(ChannelError::InvalidTag),
        };
        self.next_receive_counter = counter.checked_add(1);
        Ok(plaintext)
    }

    /// Return the application exporter secret.
    #[must_use]
    pub fn exporter(&self) -> &[u8; 32] {
        &self.exporter
    }

    /// Return the transcript hash bound to this channel.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 64] {
        self.transcript_hash
    }

    fn fail<T>(&mut self, error: ChannelError) -> Result<T, ChannelError> {
        self.terminal = true;
        Err(error)
    }
}

/// XOR one direction IV with the big-endian 96-bit encoding of `counter`.
#[must_use]
pub fn derive_nonce(iv: [u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = iv;
    for (nonce_byte, counter_byte) in nonce[4..].iter_mut().zip(counter.to_be_bytes()) {
        *nonce_byte ^= counter_byte;
    }
    nonce
}

/// Encode exact deterministic CBOR additional data for one sealed frame.
pub fn sealed_aad(
    direction: Direction,
    counter: u64,
    transcript_hash: &[u8; 64],
) -> Result<Vec<u8>, ChannelError> {
    cbor2::to_canonical_vec(&Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(1.into())),
        (
            Value::Text("direction".into()),
            Value::Integer(direction_number(direction).into()),
        ),
        (
            Value::Text("counter".into()),
            Value::Integer(counter.into()),
        ),
        (
            Value::Text("th".into()),
            Value::Bytes(transcript_hash.to_vec()),
        ),
    ]))
    .map_err(|_| ChannelError::Encoding)
}

fn calculate_transcript_hash(
    public_context: &[u8],
    allocator_cpace_frame: &[u8],
    claimant_cpace_frame: &[u8],
) -> Result<[u8; 64], ChannelError> {
    let transcript = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Bytes(public_context.to_vec()),
        Value::Bytes(allocator_cpace_frame.to_vec()),
        Value::Bytes(claimant_cpace_frame.to_vec()),
    ]))
    .map_err(|_| ChannelError::Encoding)?;
    Ok(Sha512::digest(transcript).into())
}

fn expand<const LENGTH: usize>(
    hkdf: &Hkdf<Sha512>,
    label: &[u8],
    transcript_hash: &[u8; 64],
) -> Result<[u8; LENGTH], ChannelError> {
    let mut info = Vec::with_capacity(label.len() + transcript_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(transcript_hash);
    let mut result = [0_u8; LENGTH];
    hkdf.expand(&info, &mut result)
        .map_err(|_| ChannelError::KeySchedule)?;
    Ok(result)
}

fn finished(
    key: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8; 64],
) -> Result<[u8; 64], ChannelError> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| ChannelError::KeySchedule)?;
    mac.update(label);
    mac.update(transcript_hash);
    Ok(mac.finalize().into_bytes().into())
}

const fn direction_number(direction: Direction) -> u64 {
    match direction {
        Direction::AllocatorToClaimant => 0,
        Direction::ClaimantToAllocator => 1,
    }
}

const fn send_direction(side: Side) -> Direction {
    match side {
        Side::Allocator => Direction::AllocatorToClaimant,
        Side::Claimant => Direction::ClaimantToAllocator,
    }
}

const fn receive_direction(side: Side) -> Direction {
    match side {
        Side::Allocator => Direction::ClaimantToAllocator,
        Side::Claimant => Direction::AllocatorToClaimant,
    }
}
