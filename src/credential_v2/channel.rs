use super::{CredentialV2Error, CredentialV2Frame};
use crate::{
    channel::derive_nonce,
    cpace::IntermediateSessionKey,
    wire::{Direction, Side},
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

const MAX_PLAINTEXT: usize = 69_556;

/// Derived credential/v2 channel awaiting the peer's Finished value.
pub struct PendingCredentialV2Channel {
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

impl fmt::Debug for PendingCredentialV2Channel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingCredentialV2Channel([REDACTED])")
    }
}

impl PendingCredentialV2Channel {
    /// Derive the complete credential/v2 schedule from the exact transcript.
    pub fn new(
        local_side: Side,
        isk: IntermediateSessionKey,
        public_context: &[u8],
        allocator_cpace_frame: &[u8],
        claimant_cpace_frame: &[u8],
    ) -> Result<Self, CredentialV2Error> {
        let transcript_hash =
            transcript_hash(public_context, allocator_cpace_frame, claimant_cpace_frame)?;
        let hkdf = Hkdf::<Sha512>::new(Some(&[]), isk.as_bytes());
        let kc_allocator = expand::<32>(&hkdf, b"pairing-credential-v2 kc A", &transcript_hash)?;
        let kc_claimant = expand::<32>(&hkdf, b"pairing-credential-v2 kc B", &transcript_hash)?;
        let allocator_finished = finished(
            &kc_allocator,
            b"pairing-credential-v2 finished A",
            &transcript_hash,
        )?;
        let claimant_finished = finished(
            &kc_claimant,
            b"pairing-credential-v2 finished B",
            &transcript_hash,
        )?;
        let secrets = PendingSecrets {
            key_allocator_to_claimant: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-credential-v2 key A-B",
                &transcript_hash,
            )?),
            key_claimant_to_allocator: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-credential-v2 key B-A",
                &transcript_hash,
            )?),
            iv_allocator_to_claimant: Zeroizing::new(expand::<12>(
                &hkdf,
                b"pairing-credential-v2 iv A-B",
                &transcript_hash,
            )?),
            iv_claimant_to_allocator: Zeroizing::new(expand::<12>(
                &hkdf,
                b"pairing-credential-v2 iv B-A",
                &transcript_hash,
            )?),
            exporter: Zeroizing::new(expand::<32>(
                &hkdf,
                b"pairing-credential-v2 exporter",
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

    /// Return this endpoint's exact role-bound Finished frame.
    #[must_use]
    pub fn local_finished_frame(&self) -> CredentialV2Frame {
        CredentialV2Frame::Finished {
            side: self.local_side,
            value: self.local_finished,
        }
    }

    /// Return the transcript hash.
    #[must_use]
    pub const fn transcript_hash(&self) -> [u8; 64] {
        self.transcript_hash
    }

    /// Verify the peer Finished frame and activate application transport.
    pub fn confirm(
        self,
        peer_finished_frame: &CredentialV2Frame,
    ) -> Result<SecureCredentialV2Channel, CredentialV2Error> {
        let (peer_side, peer_finished) = peer_finished_frame
            .finished()
            .ok_or(CredentialV2Error::Finished)?;
        if peer_side == self.local_side
            || !bool::from(self.peer_finished.as_slice().ct_eq(peer_finished))
        {
            return Err(CredentialV2Error::Finished);
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
        Ok(SecureCredentialV2Channel {
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

/// Confirmed credential/v2 channel with role-directed exact counters.
pub struct SecureCredentialV2Channel {
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

impl fmt::Debug for SecureCredentialV2Channel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureCredentialV2Channel([REDACTED])")
    }
}

impl SecureCredentialV2Channel {
    /// Seal one plaintext with the exact next local-direction counter.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<CredentialV2Frame, CredentialV2Error> {
        if self.terminal {
            return Err(CredentialV2Error::Terminal);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(CredentialV2Error::Size);
        }
        let counter = self.next_send_counter.ok_or(CredentialV2Error::Counter)?;
        let direction = send_direction(self.local_side);
        let aad = sealed_aad(direction, counter, &self.transcript_hash)?;
        let nonce_bytes = derive_nonce(*self.send_iv, counter);
        let nonce = nonce_bytes.into();
        let cipher = Aes256Gcm::new_from_slice(self.send_key.as_slice())
            .map_err(|_| CredentialV2Error::KeySchedule)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CredentialV2Error::Authentication)?;
        self.next_send_counter = counter.checked_add(1);
        Ok(CredentialV2Frame::Sealed {
            direction,
            counter,
            ciphertext,
        })
    }

    /// Open one exact-next peer-direction sealed frame.
    pub fn open(&mut self, frame: &CredentialV2Frame) -> Result<Vec<u8>, CredentialV2Error> {
        if self.terminal {
            return Err(CredentialV2Error::Terminal);
        }
        let Some((direction, counter, ciphertext)) = frame.sealed() else {
            return self.fail(CredentialV2Error::Schema);
        };
        if direction != receive_direction(self.local_side) {
            return self.fail(CredentialV2Error::Direction);
        }
        let Some(expected) = self.next_receive_counter else {
            return self.fail(CredentialV2Error::Counter);
        };
        if counter != expected {
            return self.fail(CredentialV2Error::Counter);
        }
        if !(17..=MAX_PLAINTEXT + 16).contains(&ciphertext.len()) {
            return self.fail(CredentialV2Error::Size);
        }
        let aad = sealed_aad(direction, counter, &self.transcript_hash)?;
        let nonce_bytes = derive_nonce(*self.receive_iv, counter);
        let nonce = nonce_bytes.into();
        let cipher = Aes256Gcm::new_from_slice(self.receive_key.as_slice())
            .map_err(|_| CredentialV2Error::KeySchedule)?;
        let plaintext = match cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            Ok(value) => value,
            Err(_) => return self.fail(CredentialV2Error::Authentication),
        };
        self.next_receive_counter = counter.checked_add(1);
        Ok(plaintext)
    }

    /// Borrow the application exporter secret.
    #[must_use]
    pub fn exporter(&self) -> &[u8; 32] {
        &self.exporter
    }

    fn fail<T>(&mut self, error: CredentialV2Error) -> Result<T, CredentialV2Error> {
        self.terminal = true;
        Err(error)
    }
}

/// Encode credential/v2 AEAD additional data.
pub fn sealed_aad(
    direction: Direction,
    counter: u64,
    transcript_hash: &[u8; 64],
) -> Result<Vec<u8>, CredentialV2Error> {
    cbor2::to_canonical_vec(&Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
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
    .map_err(|_| CredentialV2Error::Schema)
}

fn transcript_hash(
    public_context: &[u8],
    allocator_cpace_frame: &[u8],
    claimant_cpace_frame: &[u8],
) -> Result<[u8; 64], CredentialV2Error> {
    let transcript = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Bytes(public_context.to_vec()),
        Value::Bytes(allocator_cpace_frame.to_vec()),
        Value::Bytes(claimant_cpace_frame.to_vec()),
    ]))
    .map_err(|_| CredentialV2Error::Schema)?;
    Ok(Sha512::digest(transcript).into())
}

fn expand<const LENGTH: usize>(
    hkdf: &Hkdf<Sha512>,
    label: &[u8],
    transcript_hash: &[u8; 64],
) -> Result<[u8; LENGTH], CredentialV2Error> {
    let mut info = Vec::with_capacity(label.len() + transcript_hash.len());
    info.extend_from_slice(label);
    info.extend_from_slice(transcript_hash);
    let mut output = [0_u8; LENGTH];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CredentialV2Error::KeySchedule)?;
    Ok(output)
}

fn finished(
    key: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8; 64],
) -> Result<[u8; 64], CredentialV2Error> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).map_err(|_| CredentialV2Error::KeySchedule)?;
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
