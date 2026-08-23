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

pub(super) struct SecureCredentialV2ChannelSnapshot {
    pub(super) local_side: Side,
    pub(super) transcript_hash: [u8; 64],
    pub(super) send_key: Zeroizing<[u8; 32]>,
    pub(super) receive_key: Zeroizing<[u8; 32]>,
    pub(super) send_iv: Zeroizing<[u8; 12]>,
    pub(super) receive_iv: Zeroizing<[u8; 12]>,
    pub(super) exporter: Zeroizing<[u8; 32]>,
    pub(super) next_send_counter: Option<u64>,
    pub(super) next_receive_counter: Option<u64>,
    pub(super) terminal: bool,
}

impl fmt::Debug for SecureCredentialV2Channel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureCredentialV2Channel([REDACTED])")
    }
}

impl SecureCredentialV2Channel {
    pub(super) fn checkpoint_snapshot(&self) -> SecureCredentialV2ChannelSnapshot {
        SecureCredentialV2ChannelSnapshot {
            local_side: self.local_side,
            transcript_hash: self.transcript_hash,
            send_key: Zeroizing::new(*self.send_key),
            receive_key: Zeroizing::new(*self.receive_key),
            send_iv: Zeroizing::new(*self.send_iv),
            receive_iv: Zeroizing::new(*self.receive_iv),
            exporter: Zeroizing::new(*self.exporter),
            next_send_counter: self.next_send_counter,
            next_receive_counter: self.next_receive_counter,
            terminal: self.terminal,
        }
    }

    pub(super) fn restore_snapshot(snapshot: SecureCredentialV2ChannelSnapshot) -> Self {
        Self {
            local_side: snapshot.local_side,
            transcript_hash: snapshot.transcript_hash,
            send_key: snapshot.send_key,
            receive_key: snapshot.receive_key,
            send_iv: snapshot.send_iv,
            receive_iv: snapshot.receive_iv,
            exporter: snapshot.exporter,
            next_send_counter: snapshot.next_send_counter,
            next_receive_counter: snapshot.next_receive_counter,
            terminal: snapshot.terminal,
        }
    }

    pub(super) const fn local_side(&self) -> Side {
        self.local_side
    }

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

#[cfg(test)]
mod independent_tests {
    use super::*;
    use crate::{
        cpace,
        credential_v2::{
            encode_carrier, encode_frame, CredentialV2Carrier, CredentialV2CarrierInput,
            CredentialV2Context, CredentialV2Frame, CredentialV2Presence,
        },
    };
    use hmac::{Hmac, Mac};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    fn oracle_bytes(output: &Value, key: &str) -> Vec<u8> {
        hex::decode(output[key].as_str().expect("oracle hex string")).expect("oracle hex")
    }

    #[test]
    fn test_066_python_oracle_reproduces_complete_v2_schedule_and_first_frame() {
        let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
            application_context: "https://chat.anuna.io/selfsame/v2".into(),
            relay_origin: "https://chat.anuna.io:9443".into(),
            mailbox_id: [0x11; 32],
            carrier_ceremony_id: [0x22; 32],
            carrier_nonce: [0x33; 32],
            claim_commitment: [0x44; 32],
            relay_expires_at: 1_800_000_900,
            expected_allocator_key: Some([0x77; 32]),
        })
        .unwrap();
        let encoded_carrier = encode_carrier(&carrier).unwrap();
        let profile_digest = [0x55; 32];
        let context = CredentialV2Context::derive(&carrier, profile_digest).unwrap();
        let expected_carrier_digest: [u8; 32] = Sha256::digest(encoded_carrier).into();
        assert_eq!(carrier.digest(), expected_carrier_digest);
        let allocator_presence = CredentialV2Presence::new([0x88; 16], [0x99; 16]);
        let claimant_presence = CredentialV2Presence::new([0x88; 16], [0x99; 16]);
        let allocator_scalar = [0x0a; 32];
        let (allocator_state, allocator_message) = context
            .start_cpace(Side::Allocator, &allocator_presence, allocator_scalar)
            .unwrap();
        let (claimant_state, claimant_message) = context
            .start_cpace(Side::Claimant, &claimant_presence, [0x0b; 32])
            .unwrap();
        let allocator_frame = CredentialV2Frame::cpace(&allocator_message).unwrap();
        let claimant_frame = CredentialV2Frame::cpace(&claimant_message).unwrap();
        let allocator_frame_bytes = encode_frame(&allocator_frame).unwrap();
        let claimant_frame_bytes = encode_frame(&claimant_frame).unwrap();
        let plaintext = b"independent credential/v2 oracle";
        let input = json!({
            "allocator_scalar": hex::encode(allocator_scalar),
            "sid": hex::encode(context.session_id()),
            "allocator_share": hex::encode(allocator_message.share),
            "allocator_ad": hex::encode(&allocator_message.associated_data),
            "claimant_share": hex::encode(claimant_message.share),
            "claimant_ad": hex::encode(&claimant_message.associated_data),
            "public_context": hex::encode(context.public_context()),
            "allocator_frame": hex::encode(&allocator_frame_bytes),
            "claimant_frame": hex::encode(&claimant_frame_bytes),
            "plaintext": hex::encode(plaintext),
        });
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/credential_v2_oracle.py"
        );
        let mut child = Command::new("python3")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 oracle starts");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(serde_json::to_string(&input).unwrap().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "oracle failed: {output:?}");
        let oracle: Value = serde_json::from_slice(&output.stdout).unwrap();

        let allocator_isk = cpace::finish(allocator_state, &claimant_message).unwrap();
        let claimant_isk = cpace::finish(claimant_state, &allocator_message).unwrap();
        assert_eq!(
            allocator_isk.as_bytes().as_slice(),
            oracle_bytes(&oracle, "isk")
        );
        assert_eq!(claimant_isk.as_bytes(), allocator_isk.as_bytes());
        let mut extract = Hmac::<Sha512>::new_from_slice(&[]).unwrap();
        extract.update(allocator_isk.as_bytes());
        assert_eq!(
            extract.finalize().into_bytes().as_slice(),
            oracle_bytes(&oracle, "prk")
        );
        let hkdf = Hkdf::<Sha512>::new(Some(&[]), allocator_isk.as_bytes());
        assert_eq!(
            expand::<32>(
                &hkdf,
                b"pairing-credential-v2 kc A",
                &oracle_bytes(&oracle, "th").try_into().unwrap()
            )
            .unwrap(),
            oracle_bytes(&oracle, "kc_allocator").as_slice()
        );
        assert_eq!(
            expand::<32>(
                &hkdf,
                b"pairing-credential-v2 kc B",
                &oracle_bytes(&oracle, "th").try_into().unwrap()
            )
            .unwrap(),
            oracle_bytes(&oracle, "kc_claimant").as_slice()
        );

        let pending_allocator = PendingCredentialV2Channel::new(
            Side::Allocator,
            allocator_isk,
            context.public_context(),
            &allocator_frame_bytes,
            &claimant_frame_bytes,
        )
        .unwrap();
        let pending_claimant = PendingCredentialV2Channel::new(
            Side::Claimant,
            claimant_isk,
            context.public_context(),
            &allocator_frame_bytes,
            &claimant_frame_bytes,
        )
        .unwrap();
        assert_eq!(
            pending_allocator.transcript_hash.as_slice(),
            oracle_bytes(&oracle, "th")
        );
        assert_eq!(
            pending_allocator.local_finished.as_slice(),
            oracle_bytes(&oracle, "finished_allocator")
        );
        assert_eq!(
            pending_allocator.peer_finished.as_slice(),
            oracle_bytes(&oracle, "finished_claimant")
        );
        assert_eq!(
            pending_allocator
                .secrets
                .key_allocator_to_claimant
                .as_slice(),
            oracle_bytes(&oracle, "key_allocator_to_claimant")
        );
        assert_eq!(
            pending_allocator
                .secrets
                .key_claimant_to_allocator
                .as_slice(),
            oracle_bytes(&oracle, "key_claimant_to_allocator")
        );
        assert_eq!(
            pending_allocator
                .secrets
                .iv_allocator_to_claimant
                .as_slice(),
            oracle_bytes(&oracle, "iv_allocator_to_claimant")
        );
        assert_eq!(
            pending_allocator
                .secrets
                .iv_claimant_to_allocator
                .as_slice(),
            oracle_bytes(&oracle, "iv_claimant_to_allocator")
        );
        assert_eq!(
            pending_allocator.secrets.exporter.as_slice(),
            oracle_bytes(&oracle, "exporter")
        );

        let finished_allocator = pending_allocator.local_finished_frame();
        let finished_claimant = pending_claimant.local_finished_frame();
        let mut allocator_channel = pending_allocator.confirm(&finished_claimant).unwrap();
        let _claimant_channel = pending_claimant.confirm(&finished_allocator).unwrap();
        let aad = sealed_aad(
            Direction::AllocatorToClaimant,
            0,
            &allocator_channel.transcript_hash,
        )
        .unwrap();
        assert_eq!(aad, oracle_bytes(&oracle, "aad_allocator_counter_zero"));
        assert_eq!(
            derive_nonce(*allocator_channel.send_iv, 0).as_slice(),
            oracle_bytes(&oracle, "nonce_allocator_counter_zero")
        );
        let sealed = allocator_channel.seal(plaintext).unwrap();
        let (_, counter, ciphertext) = sealed.sealed().unwrap();
        assert_eq!(counter, 0);
        assert_eq!(
            ciphertext,
            oracle_bytes(&oracle, "ciphertext_allocator_counter_zero")
        );
    }
}
