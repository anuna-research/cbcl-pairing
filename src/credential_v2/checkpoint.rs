use super::channel::SecureCredentialV2ChannelSnapshot;
use super::{
    decode_canonical, decode_object, encode_carrier, fixed_bytes, CredentialV2BodyVerifier,
    CredentialV2Carrier, CredentialV2Endpoint, CredentialV2Error, CredentialV2Kind,
    CredentialV2Phase, CredentialV2RelayState, SecureCredentialV2Channel,
};
use crate::wire::Side;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use ciborium::Value;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

const PROFILE: &str = "anuna.io/credential/v2";
const OUTER_DOMAIN: &str = "cbcl-pairing-endpoint-checkpoint/v2";
const KEY_INFO_DOMAIN: &str = "cbcl-pairing checkpoint key/v2";
const INNER_DOMAIN: &[u8] = b"cbcl-pairing endpoint state/v2\0";
const MAX_CIPHERTEXT: usize = 69_632;
const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - 16;

/// One-use nonce value populated only from shell CSPRNG output.
pub struct CredentialV2CheckpointNonce([u8; 12]);

impl CredentialV2CheckpointNonce {
    /// Wrap twelve fresh CSPRNG octets for one checkpoint attempt.
    #[must_use]
    pub const fn from_csprng(value: [u8; 12]) -> Self {
        Self(value)
    }

    pub(super) const fn into_bytes(self) -> [u8; 12] {
        self.0
    }
}

/// Sealed deterministic credential/v2 endpoint checkpoint.
///
/// External callers cannot construct or inspect plaintext state:
///
/// ```compile_fail
/// use cbcl_pairing::credential_v2::EndpointCheckpointV2;
/// let _ = EndpointCheckpointV2 { bytes: Vec::new() };
/// ```
pub struct EndpointCheckpointV2 {
    bytes: Vec<u8>,
}

/// Restored application reducer and its inseparable live traffic-key state.
pub struct RestoredCredentialV2Endpoint {
    endpoint: CredentialV2Endpoint,
    channel: SecureCredentialV2Channel,
    relay: CredentialV2RelayState,
}

impl RestoredCredentialV2Endpoint {
    /// Consume the restored aggregate into the two live protocol components.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialV2Endpoint,
        SecureCredentialV2Channel,
        CredentialV2RelayState,
    ) {
        (self.endpoint, self.channel, self.relay)
    }
}

impl std::fmt::Debug for RestoredCredentialV2Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RestoredCredentialV2Endpoint([REDACTED])")
    }
}

impl EndpointCheckpointV2 {
    /// Borrow the exact sealed deterministic-CBOR checkpoint bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

pub(super) struct OpenedCheckpoint {
    pub(super) plaintext: Zeroizing<Vec<u8>>,
    pub(super) expiry: Option<u64>,
    pub(super) nonce: [u8; 12],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn seal_checkpoint_plaintext(
    plaintext: &[u8],
    side: Side,
    carrier: &CredentialV2Carrier,
    wrapping_key: &[u8; 32],
    generation: u64,
    expiry: Option<u64>,
    nonce: [u8; 12],
) -> Result<EndpointCheckpointV2, CredentialV2Error> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err(CredentialV2Error::Size);
    }
    let aad = checkpoint_aad(side, carrier.carrier_ceremony_id(), generation, expiry)?;
    let key = derive_key(side, carrier.carrier_ceremony_id(), wrapping_key)?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CredentialV2Error::KeySchedule)?;
    let aes_nonce = nonce.into();
    let ciphertext = cipher
        .encrypt(
            &aes_nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CredentialV2Error::Authentication)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
        return Err(CredentialV2Error::Size);
    }
    Ok(EndpointCheckpointV2::from_bytes(encode_outer(
        side,
        carrier.carrier_ceremony_id(),
        generation,
        expiry,
        nonce,
        ciphertext,
    )?))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn open_checkpoint_plaintext(
    input: &[u8],
    wrapping_key: &[u8; 32],
    expected_side: Side,
    expected_carrier: &CredentialV2Carrier,
    expected_generation: u64,
    now: u64,
) -> Result<OpenedCheckpoint, CredentialV2Error> {
    open_checkpoint_for(input, wrapping_key, expected_side, expected_carrier,
        expected_generation, CheckpointPurpose::ResumeAt(now))
}

// Inspection never escapes as a live endpoint. Only the closed projection in
// `inspection` may call this path; ordinary restore always supplies real time.
#[derive(Clone, Copy)]
enum CheckpointPurpose { ResumeAt(u64), Inspect }

pub(super) fn inspect_checkpoint_plaintext(
    input: &[u8], wrapping_key: &[u8; 32], expected_carrier: &CredentialV2Carrier,
    expected_generation: u64,
) -> Result<OpenedCheckpoint, CredentialV2Error> {
    open_checkpoint_for(input, wrapping_key, Side::Allocator, expected_carrier,
        expected_generation, CheckpointPurpose::Inspect)
}

fn open_checkpoint_for(
    input: &[u8], wrapping_key: &[u8; 32], expected_side: Side,
    expected_carrier: &CredentialV2Carrier, expected_generation: u64,
    purpose: CheckpointPurpose,
) -> Result<OpenedCheckpoint, CredentialV2Error> {
    let outer = decode_outer(input)?;
    if outer.side != expected_side
        || outer.ceremony != *expected_carrier.carrier_ceremony_id()
        || outer.generation == 0
        || outer.generation != expected_generation
    {
        return Err(CredentialV2Error::Profile);
    }
    if let CheckpointPurpose::ResumeAt(now) = purpose {
        if outer.expiry.is_some_and(|expiry| now >= expiry) {
            return Err(CredentialV2Error::Expired);
        }
    }
    let aad = checkpoint_aad(outer.side, &outer.ceremony, outer.generation, outer.expiry)?;
    let key = derive_key(outer.side, &outer.ceremony, wrapping_key)?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CredentialV2Error::KeySchedule)?;
    let aes_nonce = outer.nonce.into();
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &aes_nonce,
                Payload {
                    msg: &outer.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CredentialV2Error::Authentication)?,
    );
    Ok(OpenedCheckpoint {
        plaintext,
        expiry: outer.expiry,
        nonce: outer.nonce,
    })
}

impl CredentialV2Endpoint {
    /// Seal the reducer's current authority before an outbound effect.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_checkpoint(
        &mut self,
        channel: &SecureCredentialV2Channel,
        relay: &CredentialV2RelayState,
        wrapping_key: &[u8; 32],
        generation: u64,
        expiry: Option<u64>,
        nonce: CredentialV2CheckpointNonce,
        now: u64,
    ) -> Result<EndpointCheckpointV2, CredentialV2Error> {
        if channel.local_side() != self.side {
            return Err(CredentialV2Error::Direction);
        }
        validate_checkpoint_phase(
            self.side,
            self.phase,
            self.receipt_released(),
            expiry,
            self.carrier.relay_expires_at(),
            now,
        )?;
        if generation == 0
            || generation != self.checkpoint_generation.saturating_add(1)
            || self.checkpoint_nonce == Some(nonce.0)
        {
            return Err(CredentialV2Error::Counter);
        }

        let plaintext = encode_inner(self, channel, relay, generation, nonce.0)?;
        let checkpoint = seal_checkpoint_plaintext(
            plaintext.as_slice(),
            self.side,
            &self.carrier,
            wrapping_key,
            generation,
            expiry,
            nonce.0,
        )?;
        self.checkpoint_generation = generation;
        self.checkpoint_nonce = Some(nonce.0);
        Ok(checkpoint)
    }

    /// Open a checkpoint only under exact caller-held bindings.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_checkpoint(
        input: &[u8],
        wrapping_key: &[u8; 32],
        expected_side: Side,
        expected_carrier: &CredentialV2Carrier,
        expected_generation: u64,
        now: u64,
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<RestoredCredentialV2Endpoint, CredentialV2Error> {
        let opened = open_checkpoint_plaintext(
            input,
            wrapping_key,
            expected_side,
            expected_carrier,
            expected_generation,
            now,
        )?;
        let (endpoint, channel, relay) = decode_inner(
            opened.plaintext.as_slice(),
            expected_side,
            expected_carrier,
            expected_generation,
            opened.nonce,
            body_verifier,
        )?;
        validate_checkpoint_phase(
            endpoint.side,
            endpoint.phase,
            endpoint.receipt_released(),
            opened.expiry,
            endpoint.carrier.relay_expires_at(),
            now,
        )?;
        Ok(RestoredCredentialV2Endpoint {
            endpoint,
            channel,
            relay,
        })
    }
}

// Decode an authenticated allocator state for an immediately consumed read-only
// projection. This is private to the credential/v2 implementation and is not a
// recovery/issuance API. Shape/terminal rules remain enforced despite expiry.
pub(super) fn inspect_allocator_endpoint(
    input: &[u8], wrapping_key: &[u8; 32], carrier: &CredentialV2Carrier,
    generation: u64, body_verifier: Box<dyn CredentialV2BodyVerifier>,
) -> Result<RestoredCredentialV2Endpoint, CredentialV2Error> {
    let opened = inspect_checkpoint_plaintext(input, wrapping_key, carrier, generation)?;
    let (endpoint, channel, relay) = decode_inner(
        &opened.plaintext, Side::Allocator, carrier, generation, opened.nonce, body_verifier,
    )?;
    if endpoint.phase == CredentialV2Phase::Terminal && !endpoint.receipt_released() {
        return Err(CredentialV2Error::Terminal);
    }
    if opened.expiry != Some(carrier.relay_expires_at()) {
        return Err(CredentialV2Error::Schema);
    }
    Ok(RestoredCredentialV2Endpoint { endpoint, channel, relay })
}

struct Outer {
    side: Side,
    ceremony: [u8; 32],
    generation: u64,
    expiry: Option<u64>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn decode_outer(input: &[u8]) -> Result<Outer, CredentialV2Error> {
    let value = decode_canonical(input)?;
    let values = value.as_array().ok_or(CredentialV2Error::Schema)?;
    let [domain, version, role, profile, ceremony, generation, expiry, nonce, ciphertext] =
        values.as_slice()
    else {
        return Err(CredentialV2Error::Schema);
    };
    if domain.as_text() != Some(OUTER_DOMAIN)
        || integer(version)? != 2
        || profile.as_text() != Some(PROFILE)
    {
        return Err(CredentialV2Error::Schema);
    }
    let side = text_side(role)?;
    let ceremony = fixed_bytes(ceremony)?;
    let generation = integer(generation)?;
    let expiry = if matches!(expiry, Value::Null) {
        None
    } else {
        Some(integer(expiry)?)
    };
    let nonce = fixed_bytes(nonce)?;
    let ciphertext = ciphertext
        .as_bytes()
        .ok_or(CredentialV2Error::Schema)?
        .clone();
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
        return Err(CredentialV2Error::Size);
    }
    Ok(Outer {
        side,
        ceremony,
        generation,
        expiry,
        nonce,
        ciphertext,
    })
}

fn encode_outer(
    side: Side,
    ceremony: &[u8; 32],
    generation: u64,
    expiry: Option<u64>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, CredentialV2Error> {
    cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(OUTER_DOMAIN.into()),
        Value::Integer(2.into()),
        Value::Text(side_text(side).into()),
        Value::Text(PROFILE.into()),
        Value::Bytes(ceremony.to_vec()),
        Value::Integer(generation.into()),
        expiry.map_or(Value::Null, |value| Value::Integer(value.into())),
        Value::Bytes(nonce.to_vec()),
        Value::Bytes(ciphertext),
    ]))
    .map_err(|_| CredentialV2Error::Schema)
}

fn checkpoint_aad(
    side: Side,
    ceremony: &[u8; 32],
    generation: u64,
    expiry: Option<u64>,
) -> Result<Vec<u8>, CredentialV2Error> {
    cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(OUTER_DOMAIN.into()),
        Value::Integer(2.into()),
        Value::Text(side_text(side).into()),
        Value::Text(PROFILE.into()),
        Value::Bytes(ceremony.to_vec()),
        Value::Integer(generation.into()),
        expiry.map_or(Value::Null, |value| Value::Integer(value.into())),
    ]))
    .map_err(|_| CredentialV2Error::Schema)
}

fn derive_key(
    side: Side,
    ceremony: &[u8; 32],
    wrapping_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CredentialV2Error> {
    let info = checkpoint_key_info(side)?;
    let hkdf = Hkdf::<Sha512>::new(Some(ceremony), wrapping_key);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| CredentialV2Error::KeySchedule)?;
    Ok(output)
}

fn checkpoint_key_info(side: Side) -> Result<Vec<u8>, CredentialV2Error> {
    cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(KEY_INFO_DOMAIN.into()),
        Value::Text(side_text(side).into()),
        Value::Text(PROFILE.into()),
    ]))
    .map_err(|_| CredentialV2Error::Schema)
}

fn encode_inner(
    endpoint: &CredentialV2Endpoint,
    channel: &SecureCredentialV2Channel,
    relay: &CredentialV2RelayState,
    generation: u64,
    nonce: [u8; 12],
) -> Result<Zeroizing<Vec<u8>>, CredentialV2Error> {
    let carrier = encode_carrier(&endpoint.carrier)?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        INNER_DOMAIN.len()
            + carrier.len()
            + endpoint
                .last
                .as_ref()
                .and_then(|last| last.bytes.as_ref())
                .map_or(0, Vec::len)
            + 128,
    ));
    output.extend_from_slice(INNER_DOMAIN);
    output.push(side_number(endpoint.side));
    append_bytes(&mut output, &carrier)?;
    output.push(phase_number(endpoint.phase));
    match endpoint.intent_digest {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value);
        }
        None => output.push(0),
    }
    match &endpoint.last {
        Some(last) => {
            output.push(1);
            output.push(side_number(last.sender));
            output.push(last.kind.number());
            output.extend_from_slice(&last.intent_digest);
            output.extend_from_slice(&last.content_hash);
            let omit_outbound_bytes =
                last.sender == endpoint.side && relay.cached_outbound.is_some();
            match last.bytes.as_ref().filter(|_| !omit_outbound_bytes) {
                Some(bytes) => {
                    output.push(1);
                    append_bytes(&mut output, bytes)?;
                }
                None => output.push(0),
            }
        }
        None => output.push(0),
    }
    let verifier_state = endpoint.body_verifier.checkpoint_state()?;
    append_bytes(&mut output, &verifier_state)?;
    output.extend_from_slice(&generation.to_be_bytes());
    output.extend_from_slice(&nonce);
    append_channel(&mut output, &channel.checkpoint_snapshot());
    append_relay(&mut output, relay)?;
    Ok(output)
}

fn decode_inner(
    input: &[u8],
    expected_side: Side,
    expected_carrier: &CredentialV2Carrier,
    expected_generation: u64,
    expected_nonce: [u8; 12],
    mut body_verifier: Box<dyn CredentialV2BodyVerifier>,
) -> Result<
    (
        CredentialV2Endpoint,
        SecureCredentialV2Channel,
        CredentialV2RelayState,
    ),
    CredentialV2Error,
> {
    let mut cursor = ByteCursor::new(input);
    if cursor.take(INNER_DOMAIN.len())? != INNER_DOMAIN {
        return Err(CredentialV2Error::Schema);
    }
    let side = number_side(cursor.byte()?)?;
    let carrier_bytes = cursor.length_prefixed(MAX_PLAINTEXT)?;
    let carrier = super::decode_carrier(carrier_bytes)?;
    if side != expected_side || &carrier != expected_carrier {
        return Err(CredentialV2Error::Profile);
    }
    let phase = number_phase(cursor.byte()?)?;
    let intent_digest = match cursor.byte()? {
        0 => None,
        1 => Some(cursor.array()?),
        _ => return Err(CredentialV2Error::Schema),
    };
    let last = match cursor.byte()? {
        0 => None,
        1 => {
            let sender = number_side(cursor.byte()?)?;
            let kind = CredentialV2Kind::from_number(u64::from(cursor.byte()?))?;
            let intent_digest = cursor.array()?;
            let content_hash = cursor.array()?;
            let bytes = match cursor.byte()? {
                0 => None,
                1 => Some(cursor.length_prefixed(MAX_CIPHERTEXT)?.to_vec()),
                _ => return Err(CredentialV2Error::Schema),
            };
            if let Some(bytes) = bytes.as_ref() {
                let object = decode_object(bytes)?;
                if object.kind() != kind
                    || object.intent_digest() != &intent_digest
                    || object.content_hash() != content_hash
                {
                    return Err(CredentialV2Error::Schema);
                }
            }
            Some(super::endpoint::LastObject {
                sender,
                bytes,
                kind,
                intent_digest,
                content_hash,
            })
        }
        _ => return Err(CredentialV2Error::Schema),
    };
    let verifier_state = cursor.length_prefixed_allow_empty(MAX_PLAINTEXT)?;
    body_verifier.restore_checkpoint_state(verifier_state)?;
    let generation = cursor.u64()?;
    let nonce = cursor.array()?;
    let channel = decode_channel(&mut cursor)?;
    let relay = decode_relay(&mut cursor)?;
    if !cursor.finished()
        || generation != expected_generation
        || nonce != expected_nonce
        || channel.local_side != side
        || channel.terminal
        || last.as_ref().is_some_and(|last| {
            last.bytes.is_none() && !(last.sender == side && relay.cached_outbound.is_some())
        })
        || !consistent_projection(phase, intent_digest, last.as_ref())
    {
        return Err(CredentialV2Error::Schema);
    }
    let endpoint = CredentialV2Endpoint {
        side,
        carrier,
        phase,
        intent_digest,
        last,
        body_verifier,
        checkpoint_generation: generation,
        checkpoint_nonce: Some(nonce),
    };
    Ok((
        endpoint,
        SecureCredentialV2Channel::restore_snapshot(channel),
        relay,
    ))
}

fn append_relay(
    output: &mut Vec<u8>,
    relay: &CredentialV2RelayState,
) -> Result<(), CredentialV2Error> {
    output.extend_from_slice(relay.membership_token.as_slice());
    output.push(relay.next_local_sequence);
    output.push(relay.next_peer_sequence);
    output.push(u8::from(relay.awaiting_ack));
    match relay.cached_outbound.as_ref() {
        Some(frame) => {
            output.push(1);
            append_bytes(output, &super::encode_frame(frame)?)?;
        }
        None => output.push(0),
    }
    Ok(())
}

fn decode_relay(cursor: &mut ByteCursor<'_>) -> Result<CredentialV2RelayState, CredentialV2Error> {
    let membership_token = Zeroizing::new(cursor.array()?);
    let next_local_sequence = cursor.byte()?;
    let next_peer_sequence = cursor.byte()?;
    let awaiting_ack = match cursor.byte()? {
        0 => false,
        1 => true,
        _ => return Err(CredentialV2Error::Schema),
    };
    let cached_outbound = match cursor.byte()? {
        0 => None,
        1 => Some(super::decode_frame(
            cursor.length_prefixed(MAX_CIPHERTEXT)?,
        )?),
        _ => return Err(CredentialV2Error::Schema),
    };
    if awaiting_ack != cached_outbound.is_some()
        || cached_outbound
            .as_ref()
            .is_some_and(|frame| !matches!(frame, super::CredentialV2Frame::Sealed { .. }))
    {
        return Err(CredentialV2Error::Schema);
    }
    Ok(CredentialV2RelayState {
        membership_token,
        next_local_sequence,
        next_peer_sequence,
        awaiting_ack,
        cached_outbound,
    })
}

fn append_channel(output: &mut Vec<u8>, channel: &SecureCredentialV2ChannelSnapshot) {
    output.push(side_number(channel.local_side));
    output.extend_from_slice(&channel.transcript_hash);
    output.extend_from_slice(channel.send_key.as_slice());
    output.extend_from_slice(channel.receive_key.as_slice());
    output.extend_from_slice(channel.send_iv.as_slice());
    output.extend_from_slice(channel.receive_iv.as_slice());
    output.extend_from_slice(channel.exporter.as_slice());
    append_counter(output, channel.next_send_counter);
    append_counter(output, channel.next_receive_counter);
    output.push(u8::from(channel.terminal));
}

fn decode_channel(
    cursor: &mut ByteCursor<'_>,
) -> Result<SecureCredentialV2ChannelSnapshot, CredentialV2Error> {
    let local_side = number_side(cursor.byte()?)?;
    let transcript_hash = cursor.array()?;
    let send_key = Zeroizing::new(cursor.array()?);
    let receive_key = Zeroizing::new(cursor.array()?);
    let send_iv = Zeroizing::new(cursor.array()?);
    let receive_iv = Zeroizing::new(cursor.array()?);
    let exporter = Zeroizing::new(cursor.array()?);
    let next_send_counter = cursor.counter()?;
    let next_receive_counter = cursor.counter()?;
    let terminal = match cursor.byte()? {
        0 => false,
        1 => true,
        _ => return Err(CredentialV2Error::Schema),
    };
    Ok(SecureCredentialV2ChannelSnapshot {
        local_side,
        transcript_hash,
        send_key,
        receive_key,
        send_iv,
        receive_iv,
        exporter,
        next_send_counter,
        next_receive_counter,
        terminal,
    })
}

fn append_counter(output: &mut Vec<u8>, counter: Option<u64>) {
    match counter {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn consistent_projection(
    phase: CredentialV2Phase,
    intent_digest: Option<[u8; 32]>,
    last: Option<&super::endpoint::LastObject>,
) -> bool {
    match (phase, intent_digest, last) {
        (CredentialV2Phase::Begin, None, None) => true,
        (CredentialV2Phase::Offered, Some(intent), Some(last)) => {
            last_kind(last) == Some((CredentialV2Kind::Offer, intent))
        }
        (CredentialV2Phase::IntentApproved, Some(intent), Some(last)) => {
            last_kind(last) == Some((CredentialV2Kind::IntentApprove, intent))
        }
        (CredentialV2Phase::Prepared, Some(intent), Some(last)) => {
            last_kind(last) == Some((CredentialV2Kind::Preparation, intent))
        }
        (CredentialV2Phase::Confirmed, Some(intent), Some(last)) => {
            last_kind(last).is_some_and(|(kind, found)| {
                found == intent
                    && matches!(
                        kind,
                        CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed
                    )
            })
        }
        (CredentialV2Phase::FinalApproved, Some(intent), Some(last)) => {
            last_kind(last) == Some((CredentialV2Kind::FinalApprove, intent))
        }
        (CredentialV2Phase::PayloadSent, Some(intent), Some(last)) => {
            last_kind(last) == Some((CredentialV2Kind::Payload, intent))
        }
        // The one checkpointable Terminal: the allocator has released its own
        // Receipt and may still have to retransmit it after a restart.
        (CredentialV2Phase::Terminal, Some(intent), Some(last)) => {
            last.sender == Side::Allocator
                && last_kind(last) == Some((CredentialV2Kind::Receipt, intent))
        }
        _ => false,
    }
}

fn last_kind(last: &super::endpoint::LastObject) -> Option<(CredentialV2Kind, [u8; 32])> {
    Some((last.kind, last.intent_digest))
}

fn validate_checkpoint_phase(
    side: Side,
    phase: CredentialV2Phase,
    receipt_released: bool,
    expiry: Option<u64>,
    carrier_expiry: u64,
    now: u64,
) -> Result<(), CredentialV2Error> {
    // The allocator's Receipt is the `PayloadSent -> Terminal` edge, and it is
    // released behind a checkpoint like every other frame: a Terminal
    // allocator whose last object is its own Receipt is checkpointable. Every
    // other Terminal endpoint reached that phase through a failure.
    if phase == CredentialV2Phase::Terminal && !(side == Side::Allocator && receipt_released) {
        return Err(CredentialV2Error::Terminal);
    }
    match side {
        Side::Allocator => match expiry {
            Some(value) if value == carrier_expiry && now < value => Ok(()),
            Some(_) if now >= carrier_expiry => Err(CredentialV2Error::Expired),
            _ => Err(CredentialV2Error::Schema),
        },
        Side::Claimant if phase == CredentialV2Phase::PayloadSent => {
            if expiry.is_none() {
                Ok(())
            } else {
                Err(CredentialV2Error::Schema)
            }
        }
        Side::Claimant if phase == CredentialV2Phase::FinalApproved => match expiry {
            Some(value) if value == carrier_expiry && now < value => Ok(()),
            Some(_) if now >= carrier_expiry => Err(CredentialV2Error::Expired),
            _ => Err(CredentialV2Error::Schema),
        },
        Side::Claimant => Err(CredentialV2Error::Phase),
    }
}

struct ByteCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> ByteCursor<'a> {
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
        Ok(*self.take(1)?.first().ok_or(CredentialV2Error::Schema)?)
    }

    fn u64(&mut self) -> Result<u64, CredentialV2Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], CredentialV2Error> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| CredentialV2Error::Schema)
    }

    fn length_prefixed(&mut self, maximum: usize) -> Result<&'a [u8], CredentialV2Error> {
        let value = self.length_prefixed_allow_empty(maximum)?;
        if value.is_empty() {
            return Err(CredentialV2Error::Size);
        }
        Ok(value)
    }

    fn length_prefixed_allow_empty(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], CredentialV2Error> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| CredentialV2Error::Size)?;
        if length > maximum {
            return Err(CredentialV2Error::Size);
        }
        self.take(length)
    }

    fn counter(&mut self) -> Result<Option<u64>, CredentialV2Error> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(CredentialV2Error::Schema),
        }
    }

    fn finished(&self) -> bool {
        self.position == self.input.len()
    }
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CredentialV2Error> {
    let length = u32::try_from(value.len()).map_err(|_| CredentialV2Error::Size)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn integer(value: &Value) -> Result<u64, CredentialV2Error> {
    let Value::Integer(value) = value else {
        return Err(CredentialV2Error::Schema);
    };
    u64::try_from(*value).map_err(|_| CredentialV2Error::Schema)
}

fn text_side(value: &Value) -> Result<Side, CredentialV2Error> {
    match value.as_text() {
        Some("allocator") => Ok(Side::Allocator),
        Some("claimant") => Ok(Side::Claimant),
        _ => Err(CredentialV2Error::Schema),
    }
}

const fn side_text(side: Side) -> &'static str {
    match side {
        Side::Allocator => "allocator",
        Side::Claimant => "claimant",
    }
}

const fn side_number(side: Side) -> u8 {
    match side {
        Side::Allocator => 0,
        Side::Claimant => 1,
    }
}

const fn number_side(value: u8) -> Result<Side, CredentialV2Error> {
    match value {
        0 => Ok(Side::Allocator),
        1 => Ok(Side::Claimant),
        _ => Err(CredentialV2Error::Schema),
    }
}

const fn phase_number(phase: CredentialV2Phase) -> u8 {
    match phase {
        CredentialV2Phase::Begin => 0,
        CredentialV2Phase::Offered => 1,
        CredentialV2Phase::IntentApproved => 2,
        CredentialV2Phase::Prepared => 3,
        CredentialV2Phase::Confirmed => 4,
        CredentialV2Phase::FinalApproved => 5,
        CredentialV2Phase::PayloadSent => 6,
        CredentialV2Phase::Terminal => 7,
    }
}

const fn number_phase(value: u8) -> Result<CredentialV2Phase, CredentialV2Error> {
    match value {
        0 => Ok(CredentialV2Phase::Begin),
        1 => Ok(CredentialV2Phase::Offered),
        2 => Ok(CredentialV2Phase::IntentApproved),
        3 => Ok(CredentialV2Phase::Prepared),
        4 => Ok(CredentialV2Phase::Confirmed),
        5 => Ok(CredentialV2Phase::FinalApproved),
        6 => Ok(CredentialV2Phase::PayloadSent),
        7 => Ok(CredentialV2Phase::Terminal),
        _ => Err(CredentialV2Error::Schema),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_checkpoint_key_vector_is_exact() {
        assert_eq!(
            hex::encode(checkpoint_key_info(Side::Allocator).unwrap()),
            "83781e6362636c2d70616972696e6720636865636b706f696e74206b65792f763269616c6c6f6361746f7276616e756e612e696f2f63726564656e7469616c2f7632"
        );
        assert_eq!(
            hex::encode(
                derive_key(Side::Allocator, &[0x21; 32], &[0xa1; 32])
                    .unwrap()
                    .as_slice()
            ),
            "afb3660ca39fa5c02f6b40422398bfb0487d80a7064a2aa4f00c4458489e82ca"
        );
    }
}
