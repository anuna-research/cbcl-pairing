//! Canonical SPEC-072 wire values and trust-boundary recognisers.

use std::{collections::BTreeSet, fmt, io::Cursor, sync::OnceLock};

use cddl_cat::{cbor::validate_cbor, context::BasicContext, flatten::flatten_from_str};
use ciborium::Value;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CDDL_SOURCE: &str = include_str!("../schemas/pairing-v1.cddl");

static CDDL_CONTEXT: OnceLock<Result<BasicContext, ()>> = OnceLock::new();

/// Fixed suite identifier for version 1.
pub const SUITE_ID: &str = "CPACE25519-SHA512-D21";

/// A credential/v2 claimant mailbox bearer.
///
/// Debug output is redacted and the owned bytes are erased on drop.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimToken([u8; 16]);

impl ClaimToken {
    /// Take ownership of one fully recognised raw claim token.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact token octets for the protocol commitment.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for ClaimToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClaimToken(REDACTED)")
    }
}

/// Derive the credential/v2 mailbox claim commitment.
#[must_use]
pub fn claim_commitment(mailbox_id: [u8; 32], claim_token: &ClaimToken) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"cbcl-pairing claim-v2 commitment\0");
    digest.update(mailbox_id);
    digest.update(claim_token.as_bytes());
    digest.finalize().into()
}

/// A direct mailbox identifier or relay nameplate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Locator {
    /// A random 32-octet mailbox identifier.
    Direct([u8; 32]),
    /// A numeric relay nameplate.
    Nameplate(u32),
}

/// Fully recognised pairing invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    /// Application profile identifier.
    pub application: String,
    /// Canonical HTTPS or WSS relay origin.
    pub relay_origin: String,
    /// Direct mailbox or nameplate locator.
    pub locator: Locator,
    /// Exact password-related secret octets.
    pub secret: Vec<u8>,
    /// Optional expected allocator ceremony-key digest.
    pub expected_allocator_key: Option<[u8; 32]>,
    /// Optional expected claimant ceremony-key digest.
    pub expected_claimant_key: Option<[u8; 32]>,
}

/// Fully recognised client-to-relay command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    /// Bind version 1 to a new connection.
    Bind,
    /// Allocate a mailbox with an optional lifetime.
    Allocate {
        /// Direct or nameplate locator mode.
        locator_mode: u8,
        /// Requested lifetime in seconds.
        ttl_seconds: Option<u16>,
    },
    /// Claim a mailbox locator.
    Claim(Locator),
    /// Allocate one protected credential/v2 mailbox.
    AllocateV2 {
        /// Allocator-generated direct mailbox identifier.
        mailbox_id: [u8; 32],
        /// Commitment to the separate claimant presence token.
        claim_commitment: [u8; 32],
        /// Omitted or exact credential/v2 lifetime.
        ttl_seconds: Option<u16>,
    },
    /// Claim one protected credential/v2 mailbox.
    ClaimV2 {
        /// Direct mailbox identifier from the machine carrier.
        mailbox_id: [u8; 32],
        /// Separate human-presence claim token.
        claim_token: ClaimToken,
    },
    /// Resume an existing membership.
    Open {
        /// Mailbox identifier.
        mailbox_id: [u8; 32],
        /// Secret membership token.
        membership_token: [u8; 32],
    },
    /// Queue one contiguous opaque body.
    Put {
        /// Membership-local sequence number.
        seq: u8,
        /// Opaque body bytes.
        body: Vec<u8>,
    },
    /// Acknowledge one peer sequence.
    Ack {
        /// Peer sequence number.
        peer_seq: u8,
    },
    /// Close the mailbox.
    Close,
    /// Test liveness.
    Ping,
}

/// Terminal relay close reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// Explicit close.
    Closed,
    /// A third membership attempted to claim.
    Crowded,
    /// Original absolute expiry elapsed.
    Expired,
    /// An existing sequence carried a different body.
    Conflict,
}

/// Fully recognised relay-to-client message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerMessage {
    /// Version 1 welcome.
    Welcome,
    /// Successful mailbox allocation.
    Allocated {
        /// Mailbox identifier.
        mailbox_id: [u8; 32],
        /// Allocator membership token.
        membership_token: [u8; 32],
        /// Optional reserved nameplate.
        nameplate: Option<u32>,
        /// Absolute Unix expiry in seconds.
        expires_at: u64,
    },
    /// Successful first claim.
    Claimed {
        /// Mailbox identifier.
        mailbox_id: [u8; 32],
        /// Claimant membership token.
        membership_token: [u8; 32],
        /// Absolute Unix expiry in seconds.
        expires_at: u64,
    },
    /// Successful protected credential/v2 mailbox allocation.
    AllocatedV2 {
        /// Allocator-selected mailbox identifier.
        mailbox_id: [u8; 32],
        /// Allocator membership token.
        membership_token: [u8; 32],
        /// Immutable absolute Unix expiry in seconds.
        expires_at: u64,
    },
    /// Successful protected credential/v2 mailbox claim.
    ClaimedV2 {
        /// Claimed mailbox identifier.
        mailbox_id: [u8; 32],
        /// Claimant membership token.
        membership_token: [u8; 32],
        /// Immutable absolute Unix expiry in seconds.
        expires_at: u64,
    },
    /// Opaque peer frame.
    Frame {
        /// Peer-local sequence number.
        peer_seq: u8,
        /// Opaque body.
        body: Vec<u8>,
    },
    /// Successful acknowledgement.
    Acknowledged {
        /// Local queued sequence.
        seq: u8,
    },
    /// Terminal closure.
    Closed(CloseReason),
    /// Closed-enumeration relay error.
    Error(u16),
    /// Ping response.
    Pong,
}

/// Fixed bootstrap side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// Allocator side A.
    Allocator,
    /// Claimant side B.
    Claimant,
}

/// Direction of a sealed application envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Allocator to claimant.
    AllocatorToClaimant,
    /// Claimant to allocator.
    ClaimantToAllocator,
}

/// Fully recognised CPace share and the sender's exact associated data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpaceMessage {
    /// Fixed allocator or claimant side.
    pub side: Side,
    /// Encoded Curve25519 Montgomery u-coordinate.
    pub share: [u8; 32],
    /// Deterministic `pairing-ad` bytes for this side.
    pub associated_data: Vec<u8>,
}

/// Fully recognised CPace, Finished, or sealed channel frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelFrame {
    /// One CPace protocol message and its signed CBCL control.
    Cpace {
        /// Fixed bootstrap side.
        side: Side,
        /// Canonical signed control.
        control: Vec<u8>,
        /// Exact CPace message bytes.
        message: Vec<u8>,
    },
    /// One role-bound Finished value and signed CBCL control.
    Finished {
        /// Fixed bootstrap side.
        side: Side,
        /// Canonical signed control.
        control: Vec<u8>,
        /// HMAC-SHA-512 Finished value.
        value: [u8; 64],
    },
    /// One direction-bound AEAD envelope.
    Sealed {
        /// Fixed channel direction.
        direction: Direction,
        /// Contiguous direction-local counter.
        counter: u64,
        /// Ciphertext and authentication tag.
        ciphertext: Vec<u8>,
    },
}

/// Fully recognised plaintext inside a sealed frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedPlaintext {
    /// Canonical signed CBCL control.
    pub control: Vec<u8>,
    /// Optional adjacent application body.
    pub body: Option<Vec<u8>>,
}

/// Fully recognised pairing intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingIntent {
    /// Application profile identifier.
    pub application: String,
    /// Profile-defined action.
    pub action: String,
    /// Profile-recognised allocator claim.
    pub allocator_claim: Vec<u8>,
    /// Profile-recognised claimant claim.
    pub claimant_claim: Vec<u8>,
    /// Human-readable authority summary.
    pub authority_summary: String,
    /// Fresh intent nonce.
    pub intent_nonce: [u8; 32],
}

/// Explicit user decision for one exact intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// Approve one exact intent digest.
    Approve,
    /// Decline one exact intent digest.
    Decline,
}

/// Fully recognised approval or decline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingDecision {
    /// SHA-256 digest of one canonical intent.
    pub intent_digest: [u8; 32],
    /// Explicit user decision.
    pub decision: Decision,
}

/// Fully recognised application payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationPayload {
    /// SHA-256 digest of the approved intent.
    pub intent_digest: [u8; 32],
    /// Profile-defined payload type.
    pub payload_type: String,
    /// Profile-recognised body.
    pub body: Vec<u8>,
}

/// Trust-boundary recognition or deterministic-encoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecognitionError {
    /// Input is not one complete well-formed CBOR value.
    MalformedCbor,
    /// Extra octets follow the recognised value.
    TrailingBytes,
    /// Input does not use the required deterministic encoding.
    NonDeterministic,
    /// A map contains the same key more than once.
    DuplicateKey,
    /// Input falls outside its selected CDDL rule.
    Schema,
    /// Application identifier falls outside its ABNF.
    ApplicationId,
    /// Relay origin is invalid or non-canonical.
    RelayOrigin,
    /// A CDDL-valid value cannot become its typed protocol value.
    TypedValue,
}

impl fmt::Display for RecognitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RecognitionError {}

fn cddl_context() -> Result<&'static BasicContext, RecognitionError> {
    CDDL_CONTEXT
        .get_or_init(|| {
            flatten_from_str(CDDL_SOURCE)
                .map(BasicContext::new)
                .map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| RecognitionError::Schema)
}

fn has_duplicate_key(value: &Value) -> Result<bool, RecognitionError> {
    match value {
        Value::Array(items) => {
            for item in items {
                if has_duplicate_key(item)? {
                    return Ok(true);
                }
            }
        }
        Value::Map(entries) => {
            let mut keys = BTreeSet::new();
            for (key, item) in entries {
                let canonical_key =
                    cbor2::to_canonical_vec(key).map_err(|_| RecognitionError::NonDeterministic)?;
                if !keys.insert(canonical_key) {
                    return Ok(true);
                }
                if has_duplicate_key(key)? || has_duplicate_key(item)? {
                    return Ok(true);
                }
            }
        }
        Value::Tag(_, item) if has_duplicate_key(item)? => return Ok(true),
        _ => {}
    }
    Ok(false)
}

fn recognise_value(input: &[u8], rule: &str) -> Result<Value, RecognitionError> {
    let mut cursor = Cursor::new(input);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| RecognitionError::MalformedCbor)?;
    if cursor.position() != input.len() as u64 {
        return Err(RecognitionError::TrailingBytes);
    }
    match cbor2::to_canonical_vec(&value) {
        Ok(canonical) if canonical != input => return Err(RecognitionError::NonDeterministic),
        Ok(_) => {}
        Err(_) if has_duplicate_key(&value)? => return Err(RecognitionError::DuplicateKey),
        Err(_) => return Err(RecognitionError::NonDeterministic),
    }
    if has_duplicate_key(&value)? {
        return Err(RecognitionError::DuplicateKey);
    }

    let context = cddl_context()?;
    let rule = context.rules.get(rule).ok_or(RecognitionError::Schema)?;
    validate_cbor(rule, &value, context).map_err(|_| RecognitionError::Schema)?;
    Ok(value)
}

fn deterministic_bytes(value: &Value) -> Result<Vec<u8>, RecognitionError> {
    cbor2::to_canonical_vec(value).map_err(|_| RecognitionError::TypedValue)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::Text(key.to_owned()), value))
            .collect(),
    )
}

fn map_entries(value: &Value) -> Result<&[(Value, Value)], RecognitionError> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value, RecognitionError> {
    entries
        .iter()
        .find_map(|(key, value)| match key {
            Value::Text(key) if key == name => Some(value),
            _ => None,
        })
        .ok_or(RecognitionError::TypedValue)
}

fn optional_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries.iter().find_map(|(key, value)| match key {
        Value::Text(key) if key == name => Some(value),
        _ => None,
    })
}

fn text_value(value: &Value) -> Result<&str, RecognitionError> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn bytes_value(value: &Value) -> Result<&[u8], RecognitionError> {
    match value {
        Value::Bytes(value) => Ok(value),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn uint_value(value: &Value) -> Result<u64, RecognitionError> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| RecognitionError::TypedValue),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], RecognitionError> {
    bytes_value(value)?
        .try_into()
        .map_err(|_| RecognitionError::TypedValue)
}

fn locator_value(value: &Value) -> Result<Locator, RecognitionError> {
    let Value::Array(parts) = value else {
        return Err(RecognitionError::TypedValue);
    };
    if parts.len() != 2 {
        return Err(RecognitionError::TypedValue);
    }
    match uint_value(&parts[0])? {
        0 => Ok(Locator::Direct(fixed_bytes(&parts[1])?)),
        1 => Ok(Locator::Nameplate(
            uint_value(&parts[1])?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
        )),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn encoded_locator(locator: &Locator) -> Value {
    match locator {
        Locator::Direct(mailbox_id) => Value::Array(vec![
            Value::Integer(0.into()),
            Value::Bytes(mailbox_id.to_vec()),
        ]),
        Locator::Nameplate(nameplate) => Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer(u64::from(*nameplate).into()),
        ]),
    }
}

fn valid_dns_label(label: &[u8]) -> bool {
    let Some(first) = label.first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    if label.len() == 1 {
        return true;
    }
    label[1..label.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && label
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

fn valid_application_id(application: &str) -> bool {
    if !application.is_ascii() {
        return false;
    }
    let mut parts = application.split('/');
    let (Some(domain), Some(profile), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    let mut labels = domain.as_bytes().split(|byte| *byte == b'.');
    let Some(first_label) = labels.next() else {
        return false;
    };
    if !valid_dns_label(first_label) {
        return false;
    }
    let remaining_labels: Vec<_> = labels.collect();
    if remaining_labels.is_empty() || !remaining_labels.iter().all(|label| valid_dns_label(label)) {
        return false;
    }

    let profile = profile.as_bytes();
    if !profile.first().is_some_and(u8::is_ascii_alphabetic)
        || !profile
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return false;
    }

    let Some(version) = version.strip_prefix('v') else {
        return false;
    };
    (1..=2).contains(&version.len()) && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_relay_origin(origin: &str) -> bool {
    if !origin.is_ascii() || !(origin.starts_with("https://") || origin.starts_with("wss://")) {
        return false;
    }
    let Ok(parsed) = Url::parse(origin) else {
        return false;
    };
    parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.path() == "/"
        && parsed.origin().ascii_serialization() == origin
}

fn validate_application(application: &str) -> Result<(), RecognitionError> {
    if valid_application_id(application) {
        Ok(())
    } else {
        Err(RecognitionError::ApplicationId)
    }
}

fn validate_origin(origin: &str) -> Result<(), RecognitionError> {
    if valid_relay_origin(origin) {
        Ok(())
    } else {
        Err(RecognitionError::RelayOrigin)
    }
}

fn side(value: &Value) -> Result<Side, RecognitionError> {
    match uint_value(value)? {
        0 => Ok(Side::Allocator),
        1 => Ok(Side::Claimant),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn direction(value: &Value) -> Result<Direction, RecognitionError> {
    match uint_value(value)? {
        0 => Ok(Direction::AllocatorToClaimant),
        1 => Ok(Direction::ClaimantToAllocator),
        _ => Err(RecognitionError::TypedValue),
    }
}

fn encoded_side(side: Side) -> Value {
    Value::Integer(
        match side {
            Side::Allocator => 0_u64,
            Side::Claimant => 1,
        }
        .into(),
    )
}

fn encoded_direction(direction: Direction) -> Value {
    Value::Integer(
        match direction {
            Direction::AllocatorToClaimant => 0_u64,
            Direction::ClaimantToAllocator => 1,
        }
        .into(),
    )
}

/// Recognise one deterministic pairing invitation.
pub fn decode_invitation(input: &[u8]) -> Result<Invitation, RecognitionError> {
    let value = recognise_value(input, "pairing-invitation")?;
    let entries = map_entries(&value)?;
    let application = text_value(field(entries, "application")?)?.to_owned();
    let relay_origin = text_value(field(entries, "relay-origin")?)?.to_owned();
    validate_application(&application)?;
    validate_origin(&relay_origin)?;
    Ok(Invitation {
        application,
        relay_origin,
        locator: locator_value(field(entries, "locator")?)?,
        secret: bytes_value(field(entries, "secret")?)?.to_vec(),
        expected_allocator_key: optional_field(entries, "expected-allocator-key")
            .map(fixed_bytes)
            .transpose()?,
        expected_claimant_key: optional_field(entries, "expected-claimant-key")
            .map(fixed_bytes)
            .transpose()?,
    })
}

/// Encode one recognised pairing invitation deterministically.
pub fn encode_invitation(value: &Invitation) -> Result<Vec<u8>, RecognitionError> {
    let mut entries = vec![
        ("version", Value::Integer(1.into())),
        ("suite", Value::Text(SUITE_ID.to_owned())),
        ("application", Value::Text(value.application.clone())),
        ("relay-origin", Value::Text(value.relay_origin.clone())),
        ("locator", encoded_locator(&value.locator)),
        ("secret", Value::Bytes(value.secret.clone())),
    ];
    if let Some(key) = value.expected_allocator_key {
        entries.push(("expected-allocator-key", Value::Bytes(key.to_vec())));
    }
    if let Some(key) = value.expected_claimant_key {
        entries.push(("expected-claimant-key", Value::Bytes(key.to_vec())));
    }
    let encoded = deterministic_bytes(&map(entries))?;
    decode_invitation(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic client command.
pub fn decode_client_message(input: &[u8]) -> Result<ClientMessage, RecognitionError> {
    let value = recognise_value(input, "client-message")?;
    let entries = map_entries(&value)?;
    match text_value(field(entries, "type")?)? {
        "bind" => Ok(ClientMessage::Bind),
        "allocate" => Ok(ClientMessage::Allocate {
            locator_mode: uint_value(field(entries, "locator-mode")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
            ttl_seconds: optional_field(entries, "ttl-seconds")
                .map(uint_value)
                .transpose()?
                .map(|value| value.try_into().map_err(|_| RecognitionError::TypedValue))
                .transpose()?,
        }),
        "claim" => Ok(ClientMessage::Claim(locator_value(field(
            entries, "locator",
        )?)?)),
        "allocate-v2" => Ok(ClientMessage::AllocateV2 {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            claim_commitment: fixed_bytes(field(entries, "claim-commitment")?)?,
            ttl_seconds: optional_field(entries, "ttl-seconds")
                .map(uint_value)
                .transpose()?
                .map(|value| value.try_into().map_err(|_| RecognitionError::TypedValue))
                .transpose()?,
        }),
        "claim-v2" => Ok(ClientMessage::ClaimV2 {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            claim_token: ClaimToken::new(fixed_bytes(field(entries, "claim-token")?)?),
        }),
        "open" => Ok(ClientMessage::Open {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            membership_token: fixed_bytes(field(entries, "membership-token")?)?,
        }),
        "put" => Ok(ClientMessage::Put {
            seq: uint_value(field(entries, "seq")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
            body: bytes_value(field(entries, "body")?)?.to_vec(),
        }),
        "ack" => Ok(ClientMessage::Ack {
            peer_seq: uint_value(field(entries, "peer-seq")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
        }),
        "close" => Ok(ClientMessage::Close),
        "ping" => Ok(ClientMessage::Ping),
        _ => Err(RecognitionError::TypedValue),
    }
}

/// Encode one recognised client command deterministically.
pub fn encode_client_message(value: &ClientMessage) -> Result<Vec<u8>, RecognitionError> {
    let value = match value {
        ClientMessage::Bind => map(vec![
            ("type", Value::Text("bind".into())),
            ("version", Value::Integer(1.into())),
        ]),
        ClientMessage::Allocate {
            locator_mode,
            ttl_seconds,
        } => {
            let mut entries = vec![
                ("type", Value::Text("allocate".into())),
                (
                    "locator-mode",
                    Value::Integer(u64::from(*locator_mode).into()),
                ),
            ];
            if let Some(ttl_seconds) = ttl_seconds {
                entries.push((
                    "ttl-seconds",
                    Value::Integer(u64::from(*ttl_seconds).into()),
                ));
            }
            map(entries)
        }
        ClientMessage::Claim(locator) => map(vec![
            ("type", Value::Text("claim".into())),
            ("locator", encoded_locator(locator)),
        ]),
        ClientMessage::AllocateV2 {
            mailbox_id,
            claim_commitment,
            ttl_seconds,
        } => {
            let mut entries = vec![
                ("type", Value::Text("allocate-v2".into())),
                ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
                ("claim-commitment", Value::Bytes(claim_commitment.to_vec())),
            ];
            if let Some(ttl_seconds) = ttl_seconds {
                entries.push((
                    "ttl-seconds",
                    Value::Integer(u64::from(*ttl_seconds).into()),
                ));
            }
            map(entries)
        }
        ClientMessage::ClaimV2 {
            mailbox_id,
            claim_token,
        } => map(vec![
            ("type", Value::Text("claim-v2".into())),
            ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
            ("claim-token", Value::Bytes(claim_token.as_bytes().to_vec())),
        ]),
        ClientMessage::Open {
            mailbox_id,
            membership_token,
        } => map(vec![
            ("type", Value::Text("open".into())),
            ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
            ("membership-token", Value::Bytes(membership_token.to_vec())),
        ]),
        ClientMessage::Put { seq, body } => map(vec![
            ("type", Value::Text("put".into())),
            ("seq", Value::Integer(u64::from(*seq).into())),
            ("body", Value::Bytes(body.clone())),
        ]),
        ClientMessage::Ack { peer_seq } => map(vec![
            ("type", Value::Text("ack".into())),
            ("peer-seq", Value::Integer(u64::from(*peer_seq).into())),
        ]),
        ClientMessage::Close => map(vec![("type", Value::Text("close".into()))]),
        ClientMessage::Ping => map(vec![("type", Value::Text("ping".into()))]),
    };
    let encoded = deterministic_bytes(&value)?;
    decode_client_message(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic server message.
pub fn decode_server_message(input: &[u8]) -> Result<ServerMessage, RecognitionError> {
    let value = recognise_value(input, "server-message")?;
    let entries = map_entries(&value)?;
    match text_value(field(entries, "type")?)? {
        "welcome" => Ok(ServerMessage::Welcome),
        "allocated" => Ok(ServerMessage::Allocated {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            membership_token: fixed_bytes(field(entries, "membership-token")?)?,
            nameplate: optional_field(entries, "nameplate")
                .map(uint_value)
                .transpose()?
                .map(|value| value.try_into().map_err(|_| RecognitionError::TypedValue))
                .transpose()?,
            expires_at: uint_value(field(entries, "expires-at")?)?,
        }),
        "claimed" => Ok(ServerMessage::Claimed {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            membership_token: fixed_bytes(field(entries, "membership-token")?)?,
            expires_at: uint_value(field(entries, "expires-at")?)?,
        }),
        "allocated-v2" => Ok(ServerMessage::AllocatedV2 {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            membership_token: fixed_bytes(field(entries, "membership-token")?)?,
            expires_at: uint_value(field(entries, "expires-at")?)?,
        }),
        "claimed-v2" => Ok(ServerMessage::ClaimedV2 {
            mailbox_id: fixed_bytes(field(entries, "mailbox-id")?)?,
            membership_token: fixed_bytes(field(entries, "membership-token")?)?,
            expires_at: uint_value(field(entries, "expires-at")?)?,
        }),
        "frame" => Ok(ServerMessage::Frame {
            peer_seq: uint_value(field(entries, "peer-seq")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
            body: bytes_value(field(entries, "body")?)?.to_vec(),
        }),
        "acknowledged" => Ok(ServerMessage::Acknowledged {
            seq: uint_value(field(entries, "seq")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
        }),
        "closed" => Ok(ServerMessage::Closed(
            match text_value(field(entries, "reason")?)? {
                "closed" => CloseReason::Closed,
                "crowded" => CloseReason::Crowded,
                "expired" => CloseReason::Expired,
                "conflict" => CloseReason::Conflict,
                _ => return Err(RecognitionError::TypedValue),
            },
        )),
        "error" => Ok(ServerMessage::Error(
            uint_value(field(entries, "code")?)?
                .try_into()
                .map_err(|_| RecognitionError::TypedValue)?,
        )),
        "pong" => Ok(ServerMessage::Pong),
        _ => Err(RecognitionError::TypedValue),
    }
}

/// Encode one recognised server message deterministically.
pub fn encode_server_message(value: &ServerMessage) -> Result<Vec<u8>, RecognitionError> {
    let value = match value {
        ServerMessage::Welcome => map(vec![
            ("type", Value::Text("welcome".into())),
            ("version", Value::Integer(1.into())),
        ]),
        ServerMessage::Allocated {
            mailbox_id,
            membership_token,
            nameplate,
            expires_at,
        } => {
            let mut entries = vec![
                ("type", Value::Text("allocated".into())),
                ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
                ("membership-token", Value::Bytes(membership_token.to_vec())),
                ("expires-at", Value::Integer((*expires_at).into())),
            ];
            if let Some(nameplate) = nameplate {
                entries.push(("nameplate", Value::Integer(u64::from(*nameplate).into())));
            }
            map(entries)
        }
        ServerMessage::Claimed {
            mailbox_id,
            membership_token,
            expires_at,
        } => map(vec![
            ("type", Value::Text("claimed".into())),
            ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
            ("membership-token", Value::Bytes(membership_token.to_vec())),
            ("expires-at", Value::Integer((*expires_at).into())),
        ]),
        ServerMessage::AllocatedV2 {
            mailbox_id,
            membership_token,
            expires_at,
        } => map(vec![
            ("type", Value::Text("allocated-v2".into())),
            ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
            ("membership-token", Value::Bytes(membership_token.to_vec())),
            ("expires-at", Value::Integer((*expires_at).into())),
        ]),
        ServerMessage::ClaimedV2 {
            mailbox_id,
            membership_token,
            expires_at,
        } => map(vec![
            ("type", Value::Text("claimed-v2".into())),
            ("mailbox-id", Value::Bytes(mailbox_id.to_vec())),
            ("membership-token", Value::Bytes(membership_token.to_vec())),
            ("expires-at", Value::Integer((*expires_at).into())),
        ]),
        ServerMessage::Frame { peer_seq, body } => map(vec![
            ("type", Value::Text("frame".into())),
            ("peer-seq", Value::Integer(u64::from(*peer_seq).into())),
            ("body", Value::Bytes(body.clone())),
        ]),
        ServerMessage::Acknowledged { seq } => map(vec![
            ("type", Value::Text("acknowledged".into())),
            ("seq", Value::Integer(u64::from(*seq).into())),
        ]),
        ServerMessage::Closed(reason) => map(vec![
            ("type", Value::Text("closed".into())),
            (
                "reason",
                Value::Text(
                    match reason {
                        CloseReason::Closed => "closed",
                        CloseReason::Crowded => "crowded",
                        CloseReason::Expired => "expired",
                        CloseReason::Conflict => "conflict",
                    }
                    .into(),
                ),
            ),
        ]),
        ServerMessage::Error(code) => map(vec![
            ("type", Value::Text("error".into())),
            ("code", Value::Integer(u64::from(*code).into())),
        ]),
        ServerMessage::Pong => map(vec![("type", Value::Text("pong".into()))]),
    };
    let encoded = deterministic_bytes(&value)?;
    decode_server_message(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic pairing-channel frame.
pub fn decode_channel_frame(input: &[u8]) -> Result<ChannelFrame, RecognitionError> {
    let value = recognise_value(input, "cpace-channel-frame")?;
    let entries = map_entries(&value)?;
    match text_value(field(entries, "kind")?)? {
        "cpace" => {
            let outer_side = side(field(entries, "role")?)?;
            let message = bytes_value(field(entries, "message")?)?.to_vec();
            if decode_cpace_message(&message)?.side != outer_side {
                return Err(RecognitionError::TypedValue);
            }
            Ok(ChannelFrame::Cpace {
                side: outer_side,
                control: bytes_value(field(entries, "control")?)?.to_vec(),
                message,
            })
        }
        "finished" => Ok(ChannelFrame::Finished {
            side: side(field(entries, "role")?)?,
            control: bytes_value(field(entries, "control")?)?.to_vec(),
            value: fixed_bytes(field(entries, "value")?)?,
        }),
        "sealed" => Ok(ChannelFrame::Sealed {
            direction: direction(field(entries, "direction")?)?,
            counter: uint_value(field(entries, "counter")?)?,
            ciphertext: bytes_value(field(entries, "ciphertext")?)?.to_vec(),
        }),
        _ => Err(RecognitionError::TypedValue),
    }
}

/// Encode one recognised pairing-channel frame deterministically.
pub fn encode_channel_frame(value: &ChannelFrame) -> Result<Vec<u8>, RecognitionError> {
    let value = match value {
        ChannelFrame::Cpace {
            side,
            control,
            message,
        } => map(vec![
            ("v", Value::Integer(1.into())),
            ("kind", Value::Text("cpace".into())),
            ("role", encoded_side(*side)),
            ("control", Value::Bytes(control.clone())),
            ("message", Value::Bytes(message.clone())),
        ]),
        ChannelFrame::Finished {
            side,
            control,
            value,
        } => map(vec![
            ("v", Value::Integer(1.into())),
            ("kind", Value::Text("finished".into())),
            ("role", encoded_side(*side)),
            ("control", Value::Bytes(control.clone())),
            ("value", Value::Bytes(value.to_vec())),
        ]),
        ChannelFrame::Sealed {
            direction,
            counter,
            ciphertext,
        } => map(vec![
            ("v", Value::Integer(1.into())),
            ("kind", Value::Text("sealed".into())),
            ("direction", encoded_direction(*direction)),
            ("counter", Value::Integer((*counter).into())),
            ("ciphertext", Value::Bytes(ciphertext.clone())),
        ]),
    };
    let encoded = deterministic_bytes(&value)?;
    decode_channel_frame(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic nested CPace message.
pub fn decode_cpace_message(input: &[u8]) -> Result<CpaceMessage, RecognitionError> {
    let value = recognise_value(input, "cpace-message")?;
    let Value::Array(parts) = value else {
        return Err(RecognitionError::TypedValue);
    };
    if parts.len() != 4 || uint_value(&parts[0])? != 1 {
        return Err(RecognitionError::TypedValue);
    }
    Ok(CpaceMessage {
        side: side(&parts[1])?,
        share: fixed_bytes(&parts[2])?,
        associated_data: bytes_value(&parts[3])?.to_vec(),
    })
}

/// Encode one nested CPace message as deterministic CBOR.
pub fn encode_cpace_message(value: &CpaceMessage) -> Result<Vec<u8>, RecognitionError> {
    let encoded = deterministic_bytes(&Value::Array(vec![
        Value::Integer(1.into()),
        encoded_side(value.side),
        Value::Bytes(value.share.to_vec()),
        Value::Bytes(value.associated_data.clone()),
    ]))?;
    decode_cpace_message(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic sealed plaintext.
pub fn decode_sealed_plaintext(input: &[u8]) -> Result<SealedPlaintext, RecognitionError> {
    let value = recognise_value(input, "sealed-plaintext")?;
    let entries = map_entries(&value)?;
    Ok(SealedPlaintext {
        control: bytes_value(field(entries, "control")?)?.to_vec(),
        body: optional_field(entries, "body")
            .map(bytes_value)
            .transpose()?
            .map(ToOwned::to_owned),
    })
}

/// Encode one recognised sealed plaintext deterministically.
pub fn encode_sealed_plaintext(value: &SealedPlaintext) -> Result<Vec<u8>, RecognitionError> {
    let mut entries = vec![("control", Value::Bytes(value.control.clone()))];
    if let Some(body) = &value.body {
        entries.push(("body", Value::Bytes(body.clone())));
    }
    let encoded = deterministic_bytes(&map(entries))?;
    decode_sealed_plaintext(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic pairing intent.
pub fn decode_pairing_intent(input: &[u8]) -> Result<PairingIntent, RecognitionError> {
    let value = recognise_value(input, "pairing-intent")?;
    let entries = map_entries(&value)?;
    let application = text_value(field(entries, "application")?)?.to_owned();
    validate_application(&application)?;
    Ok(PairingIntent {
        application,
        action: text_value(field(entries, "action")?)?.to_owned(),
        allocator_claim: bytes_value(field(entries, "allocator-claim")?)?.to_vec(),
        claimant_claim: bytes_value(field(entries, "claimant-claim")?)?.to_vec(),
        authority_summary: text_value(field(entries, "authority-summary")?)?.to_owned(),
        intent_nonce: fixed_bytes(field(entries, "intent-nonce")?)?,
    })
}

/// Encode one recognised pairing intent deterministically.
pub fn encode_pairing_intent(value: &PairingIntent) -> Result<Vec<u8>, RecognitionError> {
    let encoded = deterministic_bytes(&map(vec![
        ("type", Value::Text("intent".into())),
        ("application", Value::Text(value.application.clone())),
        ("action", Value::Text(value.action.clone())),
        (
            "allocator-claim",
            Value::Bytes(value.allocator_claim.clone()),
        ),
        ("claimant-claim", Value::Bytes(value.claimant_claim.clone())),
        (
            "authority-summary",
            Value::Text(value.authority_summary.clone()),
        ),
        ("intent-nonce", Value::Bytes(value.intent_nonce.to_vec())),
    ]))?;
    decode_pairing_intent(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic pairing decision.
pub fn decode_pairing_decision(input: &[u8]) -> Result<PairingDecision, RecognitionError> {
    let value = recognise_value(input, "pairing-decision")?;
    let entries = map_entries(&value)?;
    Ok(PairingDecision {
        intent_digest: fixed_bytes(field(entries, "intent-digest")?)?,
        decision: match text_value(field(entries, "decision")?)? {
            "approve" => Decision::Approve,
            "decline" => Decision::Decline,
            _ => return Err(RecognitionError::TypedValue),
        },
    })
}

/// Encode one recognised pairing decision deterministically.
pub fn encode_pairing_decision(value: &PairingDecision) -> Result<Vec<u8>, RecognitionError> {
    let encoded = deterministic_bytes(&map(vec![
        ("type", Value::Text("decision".into())),
        ("intent-digest", Value::Bytes(value.intent_digest.to_vec())),
        (
            "decision",
            Value::Text(
                match value.decision {
                    Decision::Approve => "approve",
                    Decision::Decline => "decline",
                }
                .into(),
            ),
        ),
    ]))?;
    decode_pairing_decision(&encoded)?;
    Ok(encoded)
}

/// Recognise one deterministic application payload.
pub fn decode_application_payload(input: &[u8]) -> Result<ApplicationPayload, RecognitionError> {
    let value = recognise_value(input, "application-payload")?;
    let entries = map_entries(&value)?;
    Ok(ApplicationPayload {
        intent_digest: fixed_bytes(field(entries, "intent-digest")?)?,
        payload_type: text_value(field(entries, "payload-type")?)?.to_owned(),
        body: bytes_value(field(entries, "body")?)?.to_vec(),
    })
}

/// Encode one recognised application payload deterministically.
pub fn encode_application_payload(value: &ApplicationPayload) -> Result<Vec<u8>, RecognitionError> {
    let encoded = deterministic_bytes(&map(vec![
        ("type", Value::Text("payload".into())),
        ("intent-digest", Value::Bytes(value.intent_digest.to_vec())),
        ("payload-type", Value::Text(value.payload_type.clone())),
        ("body", Value::Bytes(value.body.clone())),
    ]))?;
    decode_application_payload(&encoded)?;
    Ok(encoded)
}
