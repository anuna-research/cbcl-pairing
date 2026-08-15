//! CBCL protocol adapter for the SPEC-072 bootstrap and projected session.
//!
//! This module is intentionally an adapter over `cbcl-rs`: it does not copy
//! the causal verifier or invent a second choreography state machine.

use cbcl_core::message::{CausedBy, Message};

/// A participant's fixed role in one pairing ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    /// Creates the invitation and sends the application intent.
    Allocator,
    /// Claims the invitation and decides whether to approve it.
    Claimant,
}

/// One performative in the role-free bootstrap dialect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapPerformative {
    /// Allocator CPace public share.
    CpaceA,
    /// Claimant CPace public share.
    CpaceB,
    /// Allocator key-confirmation value.
    FinishedA,
    /// Claimant key-confirmation value.
    FinishedB,
}

/// One performative in the projected session dialect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPerformative {
    /// Allocator's pairing intent.
    Intent,
    /// Claimant's approval.
    Approve,
    /// Claimant's decline.
    Decline,
    /// Allocator's application payload.
    Payload,
}

/// The three-valued verdict returned by the underlying CBCL monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVerdict {
    /// The message is valid against the currently known causal history.
    Valid,
    /// A cited predecessor has not arrived yet.
    Unknown,
    /// The message permanently violates the installed dialect or role cast.
    Violation,
}

/// Public Ed25519 key identifier used by CBCL role casts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CeremonyKeyId(String);

impl CeremonyKeyId {
    /// Return the canonical `@ed25519:<lowercase-hex>` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Ephemeral Ed25519 signing key for one ceremony.
pub struct CeremonySigningKey;

impl CeremonySigningKey {
    /// Construct a ceremony key from exactly 32 shell-supplied secret bytes.
    pub fn from_secret(_secret: [u8; 32]) -> Result<Self, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Return the canonical public key identifier.
    pub fn key_id(&self) -> CeremonyKeyId {
        CeremonyKeyId(String::new())
    }

    /// Wrap and sign one already-typed CBCL message.
    pub fn sign_message(&self, _inner: Message) -> Result<Message, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }
}

/// Successful recognition metadata, including the CBCL causal verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    verdict: ProtocolVerdict,
    content_hash: String,
    signer: CeremonyKeyId,
}

impl Admission {
    /// Return the CBCL causal/role verdict.
    #[must_use]
    pub fn verdict(&self) -> ProtocolVerdict {
        self.verdict
    }

    /// Return the canonical full-message content address.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Return the verified signing key.
    #[must_use]
    pub fn signer(&self) -> &CeremonyKeyId {
        &self.signer
    }
}

/// Installed, hash-checked normative pairing dialects.
#[derive(Debug)]
pub struct PairingDialects;

impl PairingDialects {
    /// Install the exact sources embedded by this crate.
    pub fn install() -> Result<Self, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Install caller-supplied sources while requiring the normative hashes.
    pub fn install_sources(
        _bootstrap_source: &str,
        _session_source: &str,
    ) -> Result<Self, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }
}

/// Monotone CBCL history for the role-free CPace/Finished bootstrap.
#[derive(Debug)]
pub struct BootstrapMonitor;

impl BootstrapMonitor {
    /// Create a monitor whose thread is derived from the exact invitation.
    pub fn new(_invitation: &[u8]) -> Result<Self, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Recognise, authenticate, verify, and conditionally store one control.
    pub fn admit(
        &mut self,
        _expected: BootstrapPerformative,
        _control: &[u8],
        _adjacent_body: &[u8],
    ) -> Result<Admission, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Number of valid, distinct controls in the monotone store.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        0
    }
}

/// Monotone role-projected CBCL history after mutual key confirmation.
#[derive(Debug)]
pub struct SessionMonitor;

impl SessionMonitor {
    /// Verify and admit the inert role opener against authenticated keys.
    pub fn open(
        _invitation: &[u8],
        _local_role: PairingRole,
        _allocator: &CeremonyKeyId,
        _claimant: &CeremonyKeyId,
        _control: &[u8],
    ) -> Result<(Self, Admission), ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Recognise, authenticate, project, verify, and conditionally store one control.
    pub fn admit(
        &mut self,
        _expected: SessionPerformative,
        _control: &[u8],
        _adjacent_body: &[u8],
    ) -> Result<Admission, ProtocolError> {
        Err(ProtocolError::NotImplemented)
    }

    /// Content address of the sole inert session root.
    #[must_use]
    pub fn root_hash(&self) -> &str {
        ""
    }

    /// Number of valid, distinct messages in the session store, including its root.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        0
    }
}

/// Construct a signed bootstrap control using the normative message shape.
pub fn build_bootstrap_control(
    _key: &CeremonySigningKey,
    _performative: BootstrapPerformative,
    _ceremony: &str,
    _body: &[u8],
    _caused_by: CausedBy,
) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::NotImplemented)
}

/// Construct a signed role-projected session control.
pub fn build_session_control(
    _key: &CeremonySigningKey,
    _performative: SessionPerformative,
    _ceremony: &str,
    _recipient: &CeremonyKeyId,
    _body: &[u8],
    _caused_by: CausedBy,
) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::NotImplemented)
}

/// Construct the allocator-signed, bodyless inert role opener.
pub fn build_session_opener(
    _allocator_key: &CeremonySigningKey,
    _claimant: &CeremonyKeyId,
    _ceremony: &str,
) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::NotImplemented)
}

/// Encode a typed CBCL message in the control wire's canonical textual form.
pub fn encode_control(_message: &Message) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::NotImplemented)
}

/// Lowercase SHA-256 ceremony identifier of the exact invitation bytes.
#[must_use]
pub fn ceremony_id(_invitation: &[u8]) -> String {
    String::new()
}

/// Closed failure taxonomy for the CBCL adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Temporary red-gate sentinel removed by the implementation slice.
    NotImplemented,
    /// The normative dialect sources did not install or hash exactly.
    Dialect,
    /// The control was not a canonical bounded CBCL message.
    MalformedControl,
    /// The signed wrapper, key identifier, or signature was invalid.
    Signature,
    /// The thread did not equal the invitation-derived ceremony identifier.
    Thread,
    /// The frame kind/role did not select the control's performative.
    Performative,
    /// The adjacent body did not match the signed digest and length.
    BodyBinding,
    /// A role used a different ceremony key than its authenticated key.
    KeyBinding,
    /// The inert opener was absent, duplicated, or did not contain the exact cast.
    RoleOpener,
}
