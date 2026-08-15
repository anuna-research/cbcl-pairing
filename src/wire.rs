//! Canonical SPEC-072 wire values and trust-boundary recognisers.

use std::fmt;

/// Fixed suite identifier for version 1.
pub const SUITE_ID: &str = "CPACE25519-SHA512-D21";

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
    /// Behavioural stub used only during the Red Gate.
    NotImplemented,
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

/// Recognise one deterministic pairing invitation.
pub fn decode_invitation(_input: &[u8]) -> Result<Invitation, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised pairing invitation deterministically.
pub fn encode_invitation(_value: &Invitation) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic client command.
pub fn decode_client_message(_input: &[u8]) -> Result<ClientMessage, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised client command deterministically.
pub fn encode_client_message(_value: &ClientMessage) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic server message.
pub fn decode_server_message(_input: &[u8]) -> Result<ServerMessage, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised server message deterministically.
pub fn encode_server_message(_value: &ServerMessage) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic pairing-channel frame.
pub fn decode_channel_frame(_input: &[u8]) -> Result<ChannelFrame, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised pairing-channel frame deterministically.
pub fn encode_channel_frame(_value: &ChannelFrame) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic sealed plaintext.
pub fn decode_sealed_plaintext(_input: &[u8]) -> Result<SealedPlaintext, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised sealed plaintext deterministically.
pub fn encode_sealed_plaintext(_value: &SealedPlaintext) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic pairing intent.
pub fn decode_pairing_intent(_input: &[u8]) -> Result<PairingIntent, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised pairing intent deterministically.
pub fn encode_pairing_intent(_value: &PairingIntent) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic pairing decision.
pub fn decode_pairing_decision(_input: &[u8]) -> Result<PairingDecision, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised pairing decision deterministically.
pub fn encode_pairing_decision(_value: &PairingDecision) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Recognise one deterministic application payload.
pub fn decode_application_payload(_input: &[u8]) -> Result<ApplicationPayload, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}

/// Encode one recognised application payload deterministically.
pub fn encode_application_payload(
    _value: &ApplicationPayload,
) -> Result<Vec<u8>, RecognitionError> {
    Err(RecognitionError::NotImplemented)
}
