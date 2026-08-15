//! CBCL protocol adapter for the SPEC-072 bootstrap and projected session.
//!
//! This module is intentionally a small adapter over `cbcl-rs`. It verifies
//! the concrete signed-control profile and delegates choreography, causal
//! fan-in, role casts, and endpoint projection to the pinned CBCL engine. The
//! stores below are monotone causal histories, not a second ceremony state
//! machine; key confirmation, terminal failure, and application effects live
//! in the endpoint reducer.

use cbcl_core::attest::{verify_with_discipline, SignatureDiscipline, SigningInput};
use cbcl_core::canonical::{canonical_encode, dialect_hash};
use cbcl_core::dialect::{Dialect, DialectRegistry};
use cbcl_core::evaluator::evaluate;
use cbcl_core::message::{CausedBy, Message, Performative, Recipients, WrapperType};
use cbcl_core::projection::{project, verify_causal_for_role, LocalProtocol};
use cbcl_core::protocol::{verify_causal, VerificationResult};
use cbcl_core::r4::Signer as CbclSigner;
use cbcl_core::r6::r6_instantiated_violations;
use cbcl_core::role::{parse_wrapper_cast, AgentKey, Cast, Endpoint};
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_core::store::{ContentHash, MessageStore, ThreadId, ThreadedMessageStore};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

use crate::{
    BOOTSTRAP_DIALECT_HASH, BOOTSTRAP_DIALECT_SOURCE, BOOTSTRAP_SOURCE_SHA256,
    SESSION_DIALECT_HASH, SESSION_DIALECT_SOURCE, SESSION_SOURCE_SHA256,
};

const MAX_CONTROL_OCTETS: usize = 2_048;
const MAX_CONTROL_DEPTH: usize = 8;
const MAX_ADJACENT_BODY_OCTETS: usize = 65_536;
const KEY_PREFIX: &str = "@ed25519:";
const SHA256_PREFIX: &str = "sha256:";

/// A participant's fixed role in one pairing ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingRole {
    /// Creates the invitation and sends the application intent.
    Allocator,
    /// Claims the invitation and decides whether to approve it.
    Claimant,
}

impl PairingRole {
    fn endpoint(self) -> Endpoint {
        Endpoint {
            role: match self {
                Self::Allocator => "allocator",
                Self::Claimant => "claimant",
            }
            .into(),
            occupant: None,
        }
    }
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

impl BootstrapPerformative {
    fn name(self) -> &'static str {
        match self {
            Self::CpaceA => "cpace-a",
            Self::CpaceB => "cpace-b",
            Self::FinishedA => "finished-a",
            Self::FinishedB => "finished-b",
        }
    }

    fn role_index(self) -> usize {
        match self {
            Self::CpaceA | Self::FinishedA => 0,
            Self::CpaceB | Self::FinishedB => 1,
        }
    }

    fn is_cpace(self) -> bool {
        matches!(self, Self::CpaceA | Self::CpaceB)
    }
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

impl SessionPerformative {
    fn name(self) -> &'static str {
        match self {
            Self::Intent => "pairing-intent",
            Self::Approve => "pairing-approve",
            Self::Decline => "pairing-decline",
            Self::Payload => "pairing-payload",
        }
    }
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

impl From<VerificationResult> for ProtocolVerdict {
    fn from(value: VerificationResult) -> Self {
        match value {
            VerificationResult::Valid => Self::Valid,
            VerificationResult::Unknown => Self::Unknown,
            VerificationResult::Violation(_) => Self::Violation,
        }
    }
}

/// Public Ed25519 key identifier used by CBCL role casts.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CeremonyKeyId(String);

impl CeremonyKeyId {
    /// Parse the exact `@ed25519:<64 lowercase hex>` ceremony-key spelling.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        let hex = value
            .strip_prefix(KEY_PREFIX)
            .ok_or(ProtocolError::Signature)?;
        let bytes = decode_lower_hex::<32>(hex).ok_or(ProtocolError::Signature)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::Signature)?;
        Ok(Self(value.into()))
    }

    /// Construct the canonical identifier for a raw Ed25519 public key.
    pub fn from_public_key(public_key: [u8; 32]) -> Result<Self, ProtocolError> {
        VerifyingKey::from_bytes(&public_key).map_err(|_| ProtocolError::Signature)?;
        Ok(Self(format!("{KEY_PREFIX}{}", lower_hex(&public_key))))
    }

    /// Return the canonical `@ed25519:<lowercase-hex>` spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the raw 32-octet Ed25519 public key.
    pub fn public_key_bytes(&self) -> Result<[u8; 32], ProtocolError> {
        decode_lower_hex::<32>(
            self.0
                .strip_prefix(KEY_PREFIX)
                .ok_or(ProtocolError::Signature)?,
        )
        .ok_or(ProtocolError::Signature)
    }
}

/// Ephemeral Ed25519 signing key for one ceremony.
///
/// The wrapped `ed25519-dalek` key is zeroized on drop by its enabled
/// `zeroize` feature. This type deliberately has no `Clone` or `Debug`.
pub struct CeremonySigningKey(SigningKey);

impl CeremonySigningKey {
    /// Construct a ceremony key from exactly 32 shell-supplied secret bytes.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, ProtocolError> {
        Ok(Self(SigningKey::from_bytes(&secret)))
    }

    /// Return the canonical public key identifier.
    pub fn key_id(&self) -> CeremonyKeyId {
        CeremonyKeyId::from_public_key(self.0.verifying_key().to_bytes())
            .expect("an Ed25519 signing key always has a valid public key")
    }

    /// Wrap and sign one already-typed CBCL message.
    ///
    /// The signature uses CBCL's explicit v1/full discipline over the RFC
    /// 9804 canonical bytes of the inner message. The outer signature value
    /// is 128 lowercase hexadecimal characters.
    pub fn sign_message(&self, inner: Message) -> Result<Message, ProtocolError> {
        use ed25519_dalek::Signer as _;

        let preimage = canonical_encode(&SExpr::from(&inner));
        let signature = self.0.sign(&preimage).to_bytes();
        Ok(Message::Wrapped {
            wrapper: WrapperType::Signed,
            params: vec![
                SExpr::Atom(Atom::Symbol(self.key_id().0)),
                SExpr::Atom(Atom::Str(lower_hex(&signature))),
            ],
            content: Box::new(inner),
        })
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

/// Installed, source- and hash-checked normative pairing dialects.
#[derive(Debug, Clone)]
pub struct PairingDialects {
    registry: DialectRegistry,
}

impl PairingDialects {
    /// Install the exact sources embedded by this crate.
    pub fn install() -> Result<Self, ProtocolError> {
        Self::install_sources(BOOTSTRAP_DIALECT_SOURCE, SESSION_DIALECT_SOURCE)
    }

    /// Install caller-supplied sources while requiring all normative hashes.
    pub fn install_sources(
        bootstrap_source: &str,
        session_source: &str,
    ) -> Result<Self, ProtocolError> {
        if sha256_hex(bootstrap_source.as_bytes()) != BOOTSTRAP_SOURCE_SHA256
            || sha256_hex(session_source.as_bytes()) != SESSION_SOURCE_SHA256
        {
            return Err(ProtocolError::Dialect);
        }

        let mut registry = DialectRegistry::new();
        for source in [bootstrap_source, session_source] {
            let sexpr = cbcl_parser::parse(source).map_err(|_| ProtocolError::Dialect)?;
            let dialect = cbcl_parser::parse_dialect(&sexpr).map_err(|_| ProtocolError::Dialect)?;
            registry
                .install(dialect)
                .map_err(|_| ProtocolError::Dialect)?;
        }

        let bootstrap = registry
            .find_by_name("blind-pairing-bootstrap/v1")
            .ok_or(ProtocolError::Dialect)?;
        let session = registry
            .find_by_name("blind-pairing-session/v1")
            .ok_or(ProtocolError::Dialect)?;
        if bootstrap.hash.as_deref() != Some(BOOTSTRAP_DIALECT_HASH)
            || session.hash.as_deref() != Some(SESSION_DIALECT_HASH)
            || dialect_hash(bootstrap) != BOOTSTRAP_DIALECT_HASH
            || dialect_hash(session) != SESSION_DIALECT_HASH
        {
            return Err(ProtocolError::Dialect);
        }
        Ok(Self { registry })
    }

    /// Derive the exact local session protocol for one role through cbcl-rs.
    #[must_use]
    pub fn session_projection(&self, role: PairingRole) -> LocalProtocol {
        project(self.session(), &role.endpoint(), None)
    }

    fn bootstrap(&self) -> &Dialect {
        self.registry
            .find_by_name("blind-pairing-bootstrap/v1")
            .expect("checked during installation")
    }

    fn session(&self) -> &Dialect {
        self.registry
            .find_by_name("blind-pairing-session/v1")
            .expect("checked during installation")
    }
}

/// Monotone CBCL history for the role-free CPace/Finished bootstrap.
#[derive(Debug)]
pub struct BootstrapMonitor {
    dialects: PairingDialects,
    store: ThreadedMessageStore,
    thread: ThreadId,
    role_keys: [Option<CeremonyKeyId>; 2],
    stored: usize,
}

impl BootstrapMonitor {
    /// Create a monitor whose thread is derived from the exact invitation.
    pub fn new(invitation: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self {
            dialects: PairingDialects::install()?,
            store: ThreadedMessageStore::new(),
            thread: ThreadId(ceremony_id(invitation)),
            role_keys: [None, None],
            stored: 0,
        })
    }

    /// Recognise, authenticate, verify, and conditionally store one control.
    pub fn admit(
        &mut self,
        expected: BootstrapPerformative,
        control: &[u8],
        adjacent_body: &[u8],
    ) -> Result<Admission, ProtocolError> {
        let verified = recognise_signed_control(control, false)?;
        validate_bound_control(
            &verified.message,
            expected.name(),
            &self.thread.0,
            adjacent_body,
        )?;
        if !verified
            .message
            .innermost_simple()
            .ok_or(ProtocolError::MalformedControl)?
            .recipient_set()
            .is_empty()
        {
            return Err(ProtocolError::MalformedControl);
        }
        evaluate(&verified.message, &self.dialects.registry)
            .map_err(|_| ProtocolError::MalformedControl)?;

        let role_index = expected.role_index();
        if let Some(bound) = &self.role_keys[role_index] {
            if bound != &verified.signer {
                return Err(ProtocolError::KeyBinding);
            }
        }

        let simple = verified
            .message
            .innermost_simple()
            .ok_or(ProtocolError::MalformedControl)?;
        let protocol = self
            .dialects
            .bootstrap()
            .causal_protocol
            .as_ref()
            .ok_or(ProtocolError::Dialect)?;
        let causal = verify_causal(
            expected.name(),
            simple.caused_by(),
            &self.store,
            protocol,
            &self.thread,
        );
        let verdict = ProtocolVerdict::from(causal);

        if verdict == ProtocolVerdict::Valid {
            if !expected.is_cpace() && self.role_keys[role_index].is_none() {
                return Err(ProtocolError::KeyBinding);
            }
            if expected.is_cpace() && self.role_keys[role_index].is_none() {
                self.role_keys[role_index] = Some(verified.signer.clone());
            }
            if self.store.append(
                ContentHash(verified.content_hash.clone()),
                self.thread.clone(),
                verified.message,
            ) {
                self.stored += 1;
            }
        }

        Ok(Admission {
            verdict,
            content_hash: verified.content_hash,
            signer: verified.signer,
        })
    }

    /// Return the authenticated ceremony key first observed for a role.
    #[must_use]
    pub fn role_key(&self, role: PairingRole) -> Option<&CeremonyKeyId> {
        self.role_keys[match role {
            PairingRole::Allocator => 0,
            PairingRole::Claimant => 1,
        }]
        .as_ref()
    }

    /// Number of valid, distinct controls in the monotone store.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.stored
    }
}

/// Monotone role-projected CBCL history after mutual key confirmation.
#[derive(Debug)]
pub struct SessionMonitor {
    dialects: PairingDialects,
    store: ThreadedMessageStore,
    thread: ThreadId,
    cast: Cast,
    root: ContentHash,
    endpoint: Endpoint,
    projection: LocalProtocol,
    stored: usize,
}

impl SessionMonitor {
    /// Verify and admit the inert role opener against authenticated keys.
    pub fn open(
        invitation: &[u8],
        local_role: PairingRole,
        allocator: &CeremonyKeyId,
        claimant: &CeremonyKeyId,
        control: &[u8],
    ) -> Result<(Self, Admission), ProtocolError> {
        let dialects = PairingDialects::install()?;
        let thread = ThreadId(ceremony_id(invitation));
        let verified = recognise_signed_control(control, true)?;
        if verified.signer != *allocator {
            return Err(ProtocolError::RoleOpener);
        }
        validate_opener_simple(&verified.message, &thread.0)?;

        let Message::Wrapped {
            wrapper: WrapperType::WithRoles,
            params,
            ..
        } = &verified.message
        else {
            return Err(ProtocolError::RoleOpener);
        };
        if params != &exact_opener_params(allocator, claimant) {
            return Err(ProtocolError::RoleOpener);
        }
        let cast = parse_wrapper_cast(params, &dialects.session().roles)
            .map_err(|_| ProtocolError::RoleOpener)?;
        validate_exact_cast(&cast, allocator, claimant)?;
        if !r6_instantiated_violations(dialects.session(), &cast).is_empty() {
            return Err(ProtocolError::RoleOpener);
        }

        evaluate(&verified.message, &dialects.registry)
            .map_err(|_| ProtocolError::MalformedControl)?;
        let endpoint = local_role.endpoint();
        let root = ContentHash(verified.content_hash.clone());
        let store = ThreadedMessageStore::new();
        let verdict = ProtocolVerdict::from(verify_causal_for_role(
            &verified.message,
            &endpoint,
            dialects.session(),
            &cast,
            &store,
            &thread,
            &root,
        ));
        if verdict != ProtocolVerdict::Valid {
            return Err(ProtocolError::RoleOpener);
        }

        let projection = project(dialects.session(), &endpoint, Some(&cast));
        let mut monitor = Self {
            dialects,
            store,
            thread,
            cast,
            root,
            endpoint,
            projection,
            stored: 0,
        };
        if monitor.store.append(
            monitor.root.clone(),
            monitor.thread.clone(),
            verified.message,
        ) {
            monitor.stored = 1;
        }
        let admission = Admission {
            verdict,
            content_hash: verified.content_hash,
            signer: verified.signer,
        };
        Ok((monitor, admission))
    }

    /// Recognise, authenticate, project, verify, and conditionally store one control.
    pub fn admit(
        &mut self,
        expected: SessionPerformative,
        control: &[u8],
        adjacent_body: &[u8],
    ) -> Result<Admission, ProtocolError> {
        let verified = recognise_signed_control(control, false)?;
        validate_bound_control(
            &verified.message,
            expected.name(),
            &self.thread.0,
            adjacent_body,
        )?;
        evaluate(&verified.message, &self.dialects.registry)
            .map_err(|_| ProtocolError::MalformedControl)?;
        let simple = verified
            .message
            .innermost_simple()
            .ok_or(ProtocolError::MalformedControl)?;
        if !session_reference_is_anchored(expected, simple.caused_by(), &self.root) {
            return Ok(Admission {
                verdict: ProtocolVerdict::Violation,
                content_hash: verified.content_hash,
                signer: verified.signer,
            });
        }
        if !self.projection.steps.contains_key(expected.name()) {
            return Ok(Admission {
                verdict: ProtocolVerdict::Violation,
                content_hash: verified.content_hash,
                signer: verified.signer,
            });
        }

        let verdict = ProtocolVerdict::from(verify_causal_for_role(
            &verified.message,
            &self.endpoint,
            self.dialects.session(),
            &self.cast,
            &self.store,
            &self.thread,
            &self.root,
        ));
        if verdict == ProtocolVerdict::Valid
            && self.store.append(
                ContentHash(verified.content_hash.clone()),
                self.thread.clone(),
                verified.message,
            )
        {
            self.stored += 1;
        }
        Ok(Admission {
            verdict,
            content_hash: verified.content_hash,
            signer: verified.signer,
        })
    }

    /// Content address of the sole inert session root.
    #[must_use]
    pub fn root_hash(&self) -> &str {
        &self.root.0
    }

    /// Return the cbcl-rs-derived local protocol used by this monitor.
    #[must_use]
    pub fn projection(&self) -> &LocalProtocol {
        &self.projection
    }

    /// Number of valid, distinct messages in the session store, including its root.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.stored
    }
}

/// Construct a signed bootstrap control using the normative message shape.
pub fn build_bootstrap_control(
    key: &CeremonySigningKey,
    performative: BootstrapPerformative,
    ceremony: &str,
    body: &[u8],
    caused_by: CausedBy,
) -> Result<Vec<u8>, ProtocolError> {
    build_bound_control(key, performative.name(), None, ceremony, body, caused_by)
}

/// Construct a signed role-projected session control.
pub fn build_session_control(
    key: &CeremonySigningKey,
    performative: SessionPerformative,
    ceremony: &str,
    recipient: &CeremonyKeyId,
    body: &[u8],
    caused_by: CausedBy,
) -> Result<Vec<u8>, ProtocolError> {
    build_bound_control(
        key,
        performative.name(),
        Some(recipient),
        ceremony,
        body,
        caused_by,
    )
}

/// Construct the allocator-signed, bodyless inert role opener.
pub fn build_session_opener(
    allocator_key: &CeremonySigningKey,
    claimant: &CeremonyKeyId,
    ceremony: &str,
) -> Result<Vec<u8>, ProtocolError> {
    validate_ceremony(ceremony)?;
    let allocator = allocator_key.key_id();
    let hello = Message::Simple {
        performative: Performative::Core(cbcl_core::message::CorePerformative::Hello),
        recipient: None,
        content: SExpr::List(Vec::new()),
        params: Vec::new(),
        thread: Some(ceremony.into()),
        sender: None,
        caused_by: Some(CausedBy::Begin),
    };
    let signed = allocator_key.sign_message(hello)?;
    encode_control(&Message::Wrapped {
        wrapper: WrapperType::WithRoles,
        params: exact_opener_params(&allocator, claimant),
        content: Box::new(signed),
    })
}

/// Encode a typed CBCL message in the control wire's canonical textual form.
pub fn encode_control(message: &Message) -> Result<Vec<u8>, ProtocolError> {
    let text = SExpr::from(message).to_string();
    if text.is_empty()
        || text.len() > MAX_CONTROL_OCTETS
        || !bounded_ascii_sexpr(&text, MAX_CONTROL_DEPTH)
    {
        return Err(ProtocolError::MalformedControl);
    }
    let parsed = text
        .parse::<SExpr>()
        .map_err(|_| ProtocolError::MalformedControl)?;
    let roundtrip = Message::try_from(&parsed).map_err(|_| ProtocolError::MalformedControl)?;
    if &roundtrip != message {
        return Err(ProtocolError::MalformedControl);
    }
    Ok(text.into_bytes())
}

/// Lowercase SHA-256 ceremony identifier of the exact invitation bytes.
#[must_use]
pub fn ceremony_id(invitation: &[u8]) -> String {
    sha256_hex(invitation)
}

/// Closed failure taxonomy for the CBCL adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
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

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dialect => "normative CBCL dialect installation failed",
            Self::MalformedControl => "malformed or non-canonical CBCL control",
            Self::Signature => "CBCL control signature failed",
            Self::Thread => "CBCL control thread mismatch",
            Self::Performative => "frame-to-performative mapping mismatch",
            Self::BodyBinding => "adjacent body binding mismatch",
            Self::KeyBinding => "ceremony signing key binding mismatch",
            Self::RoleOpener => "invalid or non-normative role opener",
        })
    }
}

impl std::error::Error for ProtocolError {}

struct VerifiedControl {
    message: Message,
    signer: CeremonyKeyId,
    content_hash: String,
}

struct PublicVerifier(VerifyingKey);

impl CbclSigner for PublicVerifier {
    fn sign(&self, _data: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        let Ok(signature_bytes) = <[u8; 64]>::try_from(sig) else {
            return false;
        };
        let signature = Signature::from_bytes(&signature_bytes);
        self.0.verify_strict(data, &signature).is_ok()
    }
}

fn recognise_signed_control(
    control: &[u8],
    require_role_wrapper: bool,
) -> Result<VerifiedControl, ProtocolError> {
    if control.is_empty() || control.len() > MAX_CONTROL_OCTETS {
        return Err(ProtocolError::MalformedControl);
    }
    let text = std::str::from_utf8(control).map_err(|_| ProtocolError::MalformedControl)?;
    if !bounded_ascii_sexpr(text, MAX_CONTROL_DEPTH) {
        return Err(ProtocolError::MalformedControl);
    }
    let sexpr = text
        .parse::<SExpr>()
        .map_err(|_| ProtocolError::MalformedControl)?;
    let message = Message::try_from(&sexpr).map_err(|_| ProtocolError::MalformedControl)?;
    if SExpr::from(&message).to_string().as_bytes() != control {
        return Err(ProtocolError::MalformedControl);
    }

    let signed = if require_role_wrapper {
        let Message::Wrapped {
            wrapper: WrapperType::WithRoles,
            content,
            ..
        } = &message
        else {
            return Err(ProtocolError::RoleOpener);
        };
        content.as_ref()
    } else {
        &message
    };
    let Message::Wrapped {
        wrapper: WrapperType::Signed,
        params,
        content: inner,
    } = signed
    else {
        return Err(ProtocolError::Signature);
    };
    let [SExpr::Atom(Atom::Symbol(key)), SExpr::Atom(Atom::Str(signature_hex))] = params.as_slice()
    else {
        return Err(ProtocolError::Signature);
    };
    let signer = CeremonyKeyId::parse(key)?;
    let signature = decode_lower_hex::<64>(signature_hex).ok_or(ProtocolError::Signature)?;
    let verifying_key = VerifyingKey::from_bytes(&signer.public_key_bytes()?)
        .map_err(|_| ProtocolError::Signature)?;
    let preimage = canonical_encode(&SExpr::from(inner.as_ref()));
    verify_with_discipline(
        SignatureDiscipline::V1Full,
        &SigningInput::V1Full(&preimage),
        &PublicVerifier(verifying_key),
        &signature,
    )
    .map_err(|_| ProtocolError::Signature)?;

    let content_hash = format!(
        "{SHA256_PREFIX}{}",
        sha256_hex(&canonical_encode(&SExpr::from(&message)))
    );
    Ok(VerifiedControl {
        message,
        signer,
        content_hash,
    })
}

fn build_bound_control(
    key: &CeremonySigningKey,
    performative_name: &str,
    recipient: Option<&CeremonyKeyId>,
    ceremony: &str,
    body: &[u8],
    caused_by: CausedBy,
) -> Result<Vec<u8>, ProtocolError> {
    validate_ceremony(ceremony)?;
    if body.len() > MAX_ADJACENT_BODY_OCTETS {
        return Err(ProtocolError::BodyBinding);
    }
    let body_len = i64::try_from(body.len()).map_err(|_| ProtocolError::BodyBinding)?;
    let message = Message::Simple {
        performative: Performative::Custom(performative_name.into()),
        recipient: recipient.map(|r| Recipients::One(r.0.clone())),
        content: SExpr::Atom(Atom::Str(ceremony.into())),
        params: vec![
            SExpr::Atom(Atom::Str(format!("{SHA256_PREFIX}{}", sha256_hex(body)))),
            SExpr::Atom(Atom::Num(body_len)),
        ],
        thread: Some(ceremony.into()),
        sender: None,
        caused_by: Some(canonical_caused_by(caused_by)),
    };
    encode_control(&key.sign_message(message)?)
}

fn canonical_caused_by(caused_by: CausedBy) -> CausedBy {
    match caused_by {
        CausedBy::Multiple(mut hashes) => {
            hashes.sort();
            CausedBy::Multiple(hashes)
        }
        other => other,
    }
}

fn session_reference_is_anchored(
    performative: SessionPerformative,
    caused_by: Option<&CausedBy>,
    root: &ContentHash,
) -> bool {
    match (performative, caused_by) {
        (SessionPerformative::Intent, Some(CausedBy::Single(hash))) => hash == &root.0,
        (
            SessionPerformative::Approve
            | SessionPerformative::Decline
            | SessionPerformative::Payload,
            Some(CausedBy::Single(_)),
        ) => true,
        _ => false,
    }
}

fn validate_bound_control(
    message: &Message,
    expected_performative: &str,
    ceremony: &str,
    body: &[u8],
) -> Result<(), ProtocolError> {
    if body.len() > MAX_ADJACENT_BODY_OCTETS {
        return Err(ProtocolError::BodyBinding);
    }
    let Message::Simple {
        performative,
        content,
        params,
        thread,
        sender,
        caused_by,
        ..
    } = message
        .innermost_simple()
        .ok_or(ProtocolError::MalformedControl)?
    else {
        return Err(ProtocolError::MalformedControl);
    };
    if performative.name() != expected_performative {
        return Err(ProtocolError::Performative);
    }
    validate_ceremony(ceremony)?;
    if thread.as_deref() != Some(ceremony) {
        return Err(ProtocolError::Thread);
    }
    if sender.is_some() || caused_by.is_none() {
        return Err(ProtocolError::MalformedControl);
    }
    let [SExpr::Atom(Atom::Str(digest)), SExpr::Atom(Atom::Num(body_len))] = params.as_slice()
    else {
        return Err(ProtocolError::MalformedControl);
    };
    if content != &SExpr::Atom(Atom::Str(ceremony.into())) {
        return Err(ProtocolError::Thread);
    }
    let expected_digest = format!("{SHA256_PREFIX}{}", sha256_hex(body));
    let expected_len = i64::try_from(body.len()).map_err(|_| ProtocolError::BodyBinding)?;
    if digest != &expected_digest || *body_len != expected_len {
        return Err(ProtocolError::BodyBinding);
    }
    Ok(())
}

fn validate_opener_simple(message: &Message, ceremony: &str) -> Result<(), ProtocolError> {
    let Message::Wrapped {
        wrapper: WrapperType::WithRoles,
        content,
        ..
    } = message
    else {
        return Err(ProtocolError::RoleOpener);
    };
    let Message::Wrapped {
        wrapper: WrapperType::Signed,
        content: signed_inner,
        ..
    } = content.as_ref()
    else {
        return Err(ProtocolError::RoleOpener);
    };
    let Message::Simple {
        performative,
        recipient,
        content,
        params,
        thread,
        sender,
        caused_by,
    } = signed_inner.as_ref()
    else {
        return Err(ProtocolError::RoleOpener);
    };
    if performative.name() != "hello"
        || recipient.is_some()
        || content != &SExpr::List(Vec::new())
        || !params.is_empty()
        || thread.as_deref() != Some(ceremony)
        || sender.is_some()
        || caused_by != &Some(CausedBy::Begin)
    {
        return Err(ProtocolError::RoleOpener);
    }
    Ok(())
}

fn validate_exact_cast(
    cast: &Cast,
    allocator: &CeremonyKeyId,
    claimant: &CeremonyKeyId,
) -> Result<(), ProtocolError> {
    let expected = BTreeMap::from([
        ("allocator".into(), AgentKey(allocator.0.clone())),
        ("claimant".into(), AgentKey(claimant.0.clone())),
    ]);
    if cast.singleton != expected
        || !cast.indexed.is_empty()
        || cast.dialect_pin.as_deref() != Some(SESSION_DIALECT_HASH)
    {
        return Err(ProtocolError::RoleOpener);
    }
    Ok(())
}

fn exact_opener_params(allocator: &CeremonyKeyId, claimant: &CeremonyKeyId) -> Vec<SExpr> {
    vec![
        SExpr::List(vec![
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("allocator".into())),
                SExpr::Atom(Atom::Symbol(allocator.0.clone())),
            ]),
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("claimant".into())),
                SExpr::Atom(Atom::Symbol(claimant.0.clone())),
            ]),
        ]),
        SExpr::Atom(Atom::Keyword("dialect".into())),
        SExpr::Atom(Atom::Symbol(SESSION_DIALECT_HASH.into())),
    ]
}

fn validate_ceremony(value: &str) -> Result<(), ProtocolError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ProtocolError::Thread)
    }
}

fn bounded_ascii_sexpr(input: &str, max_depth: usize) -> bool {
    if !input.is_ascii() {
        return false;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'(' => {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            }
            b')' => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            0x20..=0x7e => {}
            _ => return false,
        }
    }
    depth == 0 && !in_string && !escaped
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        result[index] = (high << 4) | low;
    }
    Some(result)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_preflight_ignores_parentheses_inside_strings() {
        assert!(bounded_ascii_sexpr("(tell \"((((\")", 2));
        assert!(!bounded_ascii_sexpr("((((x))))", 3));
        assert!(!bounded_ascii_sexpr("(tell \"unterminated)", 8));
    }

    #[test]
    fn strict_lower_hex_roundtrips() {
        let bytes = [0x00, 0x7f, 0xa5, 0xff];
        assert_eq!(lower_hex(&bytes), "007fa5ff");
        assert_eq!(decode_lower_hex::<4>("007fa5ff"), Some(bytes));
        assert_eq!(decode_lower_hex::<4>("007FA5FF"), None);
    }
}
