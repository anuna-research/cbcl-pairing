use super::{CredentialV2Error, CredentialV2Kind, CredentialV2Object};
use sha2::{Digest, Sha256};
use std::fmt;

const MAX_APPLICATION_ID_OCTETS: usize = 2_048;
const MAX_ORIGIN_OCTETS: usize = 272;
const MAX_PERMISSION_OCTETS: usize = 128;
const MAX_PERMISSIONS: usize = 4;
const MAX_ROOMS: usize = 256;
const MAX_ROOM_OCTETS: usize = 129;
const MAX_ROOM_ARRAY_OCTETS: usize = 33_793;

/// Account values whose provenance is authenticated by the signed offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialV2AccountProvenance {
    account_principal_digest: [u8; 32],
    account_scope_id: [u8; 32],
}

impl CredentialV2AccountProvenance {
    /// Construct the two fixed-size account provenance values.
    #[must_use]
    pub const fn new(account_principal_digest: [u8; 32], account_scope_id: [u8; 32]) -> Self {
        Self {
            account_principal_digest,
            account_scope_id,
        }
    }

    /// Borrow the authenticated account-principal digest.
    #[must_use]
    pub const fn account_principal_digest(&self) -> &[u8; 32] {
        &self.account_principal_digest
    }

    /// Borrow the pending account scope identifier.
    #[must_use]
    pub const fn account_scope_id(&self) -> &[u8; 32] {
        &self.account_scope_id
    }
}

/// Installation device identity shown during consent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2DeviceBinding {
    device_did: String,
    device_key_digest: [u8; 32],
}

impl CredentialV2DeviceBinding {
    /// Construct a bounded did:key plus the authenticated installation-key digest.
    pub fn new(
        device_did: impl Into<String>,
        device_key_digest: [u8; 32],
    ) -> Result<Self, CredentialV2Error> {
        let value = Self {
            device_did: device_did.into(),
            device_key_digest,
        };
        value.validate()?;
        Ok(value)
    }

    /// Borrow the exact authenticated device DID.
    #[must_use]
    pub fn device_did(&self) -> &str {
        &self.device_did
    }

    /// Borrow the digest of the exact authenticated installation JWK.
    #[must_use]
    pub const fn device_key_digest(&self) -> &[u8; 32] {
        &self.device_key_digest
    }

    fn validate(&self) -> Result<(), CredentialV2Error> {
        let Some(encoded) = self.device_did.strip_prefix("did:key:z6Mk") else {
            return Err(CredentialV2Error::Schema);
        };
        if self.device_did.len() != 56 || encoded.len() != 44 || !encoded.bytes().all(is_base58btc)
        {
            return Err(CredentialV2Error::Schema);
        }
        Ok(())
    }
}

/// Consumer-owned contact provenance for this exact application and relay pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialV2TofuState {
    /// An explicit complete-entry gesture permits this ceremony's contact only.
    /// This neither asserts remembered trust nor authorizes a trust-row write.
    CeremonyGesture,
    /// This exact pair is being considered for the first time.
    NewPair,
    /// The person previously accepted this exact pair.
    TrustedPair,
}

/// Closed authenticated account transition shown during consent.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialV2Transition {
    /// No legacy account transition is involved.
    NoTransition,
    /// A complete authenticated Path-A-to-B transition.
    PathAToB(PathAToBDisplay),
}

impl CredentialV2Transition {
    /// Construct the bounded Path-A-to-B variant.
    pub fn path_a_to_b(
        legacy_handle: impl Into<String>,
        legacy_key_digest: [u8; 32],
        migration_rooms: Vec<String>,
        room_set_digest: [u8; 32],
        migration_snapshot_digest: [u8; 32],
        snapshot_nonce: [u8; 32],
    ) -> Result<Self, CredentialV2Error> {
        let display = PathAToBDisplay {
            legacy_handle: legacy_handle.into(),
            legacy_key_digest,
            migration_rooms,
            room_set_digest,
            migration_snapshot_digest,
            snapshot_nonce,
        };
        display.validate()?;
        Ok(Self::PathAToB(display))
    }

    /// Borrow the Path-A-to-B details when this is that variant.
    #[must_use]
    pub const fn as_path_a_to_b(&self) -> Option<&PathAToBDisplay> {
        match self {
            Self::NoTransition => None,
            Self::PathAToB(value) => Some(value),
        }
    }

    fn validate(&self) -> Result<(), CredentialV2Error> {
        match self {
            Self::NoTransition => Ok(()),
            Self::PathAToB(value) => value.validate(),
        }
    }
}

/// Private-field authenticated Path-A-to-B display data.
///
/// The transition cannot be reconstructed from UI strings:
///
/// ```compile_fail
/// use cbcl_pairing::credential_v2::PathAToBDisplay;
/// let _ = PathAToBDisplay {
///     legacy_handle: "@forged".into(),
///     legacy_key_digest: [0; 32],
///     migration_rooms: Vec::new(),
///     room_set_digest: [0; 32],
///     migration_snapshot_digest: [0; 32],
///     snapshot_nonce: [0; 32],
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PathAToBDisplay {
    legacy_handle: String,
    legacy_key_digest: [u8; 32],
    migration_rooms: Vec<String>,
    room_set_digest: [u8; 32],
    migration_snapshot_digest: [u8; 32],
    snapshot_nonce: [u8; 32],
}

impl PathAToBDisplay {
    /// Borrow the authenticated legacy handle.
    #[must_use]
    pub fn legacy_handle(&self) -> &str {
        &self.legacy_handle
    }

    /// Borrow the authenticated legacy-key digest.
    #[must_use]
    pub const fn legacy_key_digest(&self) -> &[u8; 32] {
        &self.legacy_key_digest
    }

    /// Borrow the complete authenticated sorted room set.
    #[must_use]
    pub fn migration_rooms(&self) -> &[String] {
        &self.migration_rooms
    }

    /// Borrow the authenticated room-set digest.
    #[must_use]
    pub const fn room_set_digest(&self) -> &[u8; 32] {
        &self.room_set_digest
    }

    /// Borrow the authenticated migration-snapshot digest.
    #[must_use]
    pub const fn migration_snapshot_digest(&self) -> &[u8; 32] {
        &self.migration_snapshot_digest
    }

    /// Borrow the authenticated snapshot nonce.
    #[must_use]
    pub const fn snapshot_nonce(&self) -> &[u8; 32] {
        &self.snapshot_nonce
    }

    fn validate(&self) -> Result<(), CredentialV2Error> {
        if !valid_legacy_handle(&self.legacy_handle) || self.migration_rooms.len() > MAX_ROOMS {
            return Err(CredentialV2Error::Schema);
        }
        if self.migration_rooms.iter().any(|room| !valid_room(room))
            || self
                .migration_rooms
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
            || room_array_octets(&self.migration_rooms) > MAX_ROOM_ARRAY_OCTETS
        {
            return Err(CredentialV2Error::Schema);
        }
        Ok(())
    }
}

/// Bounded claims returned by the consumer's exact signed-offer parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2IntentClaims {
    application_id: String,
    https_origin: String,
    relay_origin: String,
    carrier_ceremony_id: [u8; 32],
    account_provenance: CredentialV2AccountProvenance,
    permissions: Vec<String>,
    device_binding: CredentialV2DeviceBinding,
    transition: CredentialV2Transition,
    offer_core_digest: [u8; 32],
}

impl CredentialV2IntentClaims {
    /// Construct and validate one complete parser result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        application_id: impl Into<String>,
        https_origin: impl Into<String>,
        relay_origin: impl Into<String>,
        carrier_ceremony_id: [u8; 32],
        account_provenance: CredentialV2AccountProvenance,
        permissions: Vec<String>,
        device_binding: CredentialV2DeviceBinding,
        transition: CredentialV2Transition,
        offer_core_digest: [u8; 32],
    ) -> Result<Self, CredentialV2Error> {
        let value = Self {
            application_id: application_id.into(),
            https_origin: https_origin.into(),
            relay_origin: relay_origin.into(),
            carrier_ceremony_id,
            account_provenance,
            permissions,
            device_binding,
            transition,
            offer_core_digest,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return a test/adapter copy with a different application identifier.
    #[must_use]
    pub fn with_application_id(mut self, value: impl Into<String>) -> Self {
        self.application_id = value.into();
        self
    }

    /// Return a test/adapter copy with a different authenticated HTTPS origin.
    #[must_use]
    pub fn with_https_origin(mut self, value: impl Into<String>) -> Self {
        self.https_origin = value.into();
        self
    }

    /// Return a test/adapter copy with a different relay origin.
    #[must_use]
    pub fn with_relay_origin(mut self, value: impl Into<String>) -> Self {
        self.relay_origin = value.into();
        self
    }

    /// Return a test/adapter copy with a different carrier ceremony.
    #[must_use]
    pub const fn with_carrier_ceremony_id(mut self, value: [u8; 32]) -> Self {
        self.carrier_ceremony_id = value;
        self
    }

    /// Return a test/adapter copy with different account provenance.
    #[must_use]
    pub const fn with_account_provenance(mut self, value: CredentialV2AccountProvenance) -> Self {
        self.account_provenance = value;
        self
    }

    /// Return a test/adapter copy with a different permission set.
    #[must_use]
    pub fn with_permissions(mut self, value: Vec<String>) -> Self {
        self.permissions = value;
        self
    }

    /// Return a test/adapter copy with a different device binding.
    #[must_use]
    pub fn with_device_binding(mut self, value: CredentialV2DeviceBinding) -> Self {
        self.device_binding = value;
        self
    }

    /// Return a test/adapter copy with a different transition.
    #[must_use]
    pub fn with_transition(mut self, value: CredentialV2Transition) -> Self {
        self.transition = value;
        self
    }

    /// Return a test/adapter copy with a different offer-core digest.
    #[must_use]
    pub const fn with_offer_core_digest(mut self, value: [u8; 32]) -> Self {
        self.offer_core_digest = value;
        self
    }

    /// Borrow the canonical application identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Borrow the canonical HTTPS origin.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        &self.https_origin
    }

    /// Borrow the canonical relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        &self.relay_origin
    }

    /// Borrow the carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.carrier_ceremony_id
    }

    /// Borrow the account provenance.
    #[must_use]
    pub const fn account_provenance(&self) -> &CredentialV2AccountProvenance {
        &self.account_provenance
    }

    /// Borrow the canonical requested permission set.
    #[must_use]
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    /// Borrow the installation device binding.
    #[must_use]
    pub const fn device_binding(&self) -> &CredentialV2DeviceBinding {
        &self.device_binding
    }

    /// Borrow the authenticated transition.
    #[must_use]
    pub const fn transition(&self) -> &CredentialV2Transition {
        &self.transition
    }

    /// Borrow the digest of the exact signed offer core.
    #[must_use]
    pub const fn offer_core_digest(&self) -> &[u8; 32] {
        &self.offer_core_digest
    }

    fn validate(&self) -> Result<(), CredentialV2Error> {
        let origin = recognise_application_id(&self.application_id)?;
        recognise_origin(&self.https_origin, MAX_ORIGIN_OCTETS)?;
        recognise_origin(&self.relay_origin, MAX_ORIGIN_OCTETS)?;
        if origin != self.https_origin {
            return Err(CredentialV2Error::Schema);
        }
        if self.permissions.is_empty()
            || self.permissions.len() > MAX_PERMISSIONS
            || self
                .permissions
                .iter()
                .any(|permission| permission.is_empty() || permission.len() > MAX_PERMISSION_OCTETS)
            || self
                .permissions
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(CredentialV2Error::Schema);
        }
        self.device_binding.validate()?;
        self.transition.validate()
    }
}

/// Peer offer input constructible only through one recognised v2 Offer object.
#[derive(Debug, Eq, PartialEq)]
pub struct CredentialV2IntentInput {
    claims: CredentialV2IntentClaims,
    intent_digest: [u8; 32],
}

impl CredentialV2IntentInput {
    /// Borrow the peer application identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        self.claims.application_id()
    }

    /// Borrow the peer HTTPS origin.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        self.claims.https_origin()
    }

    /// Borrow the peer relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        self.claims.relay_origin()
    }

    /// Borrow the peer carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        self.claims.carrier_ceremony_id()
    }

    /// Borrow the peer account provenance.
    #[must_use]
    pub const fn account_provenance(&self) -> &CredentialV2AccountProvenance {
        self.claims.account_provenance()
    }

    /// Borrow the peer permission set.
    #[must_use]
    pub fn permissions(&self) -> &[String] {
        self.claims.permissions()
    }

    /// Borrow the peer device binding.
    #[must_use]
    pub const fn device_binding(&self) -> &CredentialV2DeviceBinding {
        self.claims.device_binding()
    }

    /// Borrow the peer account transition.
    #[must_use]
    pub const fn transition(&self) -> &CredentialV2Transition {
        self.claims.transition()
    }

    /// Borrow the peer signed offer-core digest.
    #[must_use]
    pub const fn offer_core_digest(&self) -> &[u8; 32] {
        self.claims.offer_core_digest()
    }

    /// Borrow the intent digest carried by the v2 object envelope.
    #[must_use]
    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }
}

/// Consumer-supplied live-authenticated authority, separate from peer bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct CredentialV2IntentAuthority {
    claims: CredentialV2IntentClaims,
    tofu_state: CredentialV2TofuState,
    intent_digest: [u8; 32],
}

impl CredentialV2IntentAuthority {
    /// Construct authority after the consumer authenticates the live profile and offer.
    pub fn new(
        claims: CredentialV2IntentClaims,
        tofu_state: CredentialV2TofuState,
    ) -> Result<Self, CredentialV2Error> {
        claims.validate()?;
        let intent_digest = credential_v2_intent_digest(*claims.offer_core_digest());
        Ok(Self {
            claims,
            tofu_state,
            intent_digest,
        })
    }

    /// Borrow the authenticated application identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        self.claims.application_id()
    }

    /// Borrow the authenticated HTTPS origin.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        self.claims.https_origin()
    }

    /// Borrow the authenticated relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        self.claims.relay_origin()
    }

    /// Borrow the authenticated carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        self.claims.carrier_ceremony_id()
    }

    /// Borrow the authenticated account provenance.
    #[must_use]
    pub const fn account_provenance(&self) -> &CredentialV2AccountProvenance {
        self.claims.account_provenance()
    }

    /// Borrow the authenticated permission set.
    #[must_use]
    pub fn permissions(&self) -> &[String] {
        self.claims.permissions()
    }

    /// Borrow the authenticated installation device binding.
    #[must_use]
    pub const fn device_binding(&self) -> &CredentialV2DeviceBinding {
        self.claims.device_binding()
    }

    /// Return the consumer-owned contact provenance for this exact pair.
    #[must_use]
    pub const fn tofu_state(&self) -> CredentialV2TofuState {
        self.tofu_state
    }

    /// Borrow the authenticated account transition.
    #[must_use]
    pub const fn transition(&self) -> &CredentialV2Transition {
        self.claims.transition()
    }

    /// Borrow the authenticated signed offer-core digest.
    #[must_use]
    pub const fn offer_core_digest(&self) -> &[u8; 32] {
        self.claims.offer_core_digest()
    }

    /// Borrow the intent digest derived from the signed offer core.
    #[must_use]
    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }
}

/// Owned credential/v2 consent display, constructible only after verification.
///
/// It has neither public fields nor a generic field-vector constructor:
///
/// ```compile_fail
/// use cbcl_pairing::credential_v2::{CredentialV2Display, CredentialV2TofuState};
/// let _ = CredentialV2Display {
///     claims: panic!("no public claims channel"),
///     tofu_state: CredentialV2TofuState::NewPair,
/// };
/// ```
///
/// It is not a serializable reconstruction token:
///
/// ```compile_fail
/// # use cbcl_pairing::credential_v2::CredentialV2Display;
/// fn reconstruct(bytes: &[u8]) -> CredentialV2Display {
///     serde_json::from_slice(bytes).unwrap()
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CredentialV2Display {
    claims: CredentialV2IntentClaims,
    tofu_state: CredentialV2TofuState,
}

impl CredentialV2Display {
    /// Borrow the authenticated application identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        self.claims.application_id()
    }

    /// Borrow the authenticated HTTPS origin.
    #[must_use]
    pub fn https_origin(&self) -> &str {
        self.claims.https_origin()
    }

    /// Borrow the authenticated relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        self.claims.relay_origin()
    }

    /// Borrow the authenticated carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        self.claims.carrier_ceremony_id()
    }

    /// Borrow the authenticated account provenance.
    #[must_use]
    pub const fn account_provenance(&self) -> &CredentialV2AccountProvenance {
        self.claims.account_provenance()
    }

    /// Borrow the authenticated requested permission set.
    #[must_use]
    pub fn permissions(&self) -> &[String] {
        self.claims.permissions()
    }

    /// Borrow the authenticated installation device binding.
    #[must_use]
    pub const fn device_binding(&self) -> &CredentialV2DeviceBinding {
        self.claims.device_binding()
    }

    /// Return the consumer-owned contact provenance, including ceremony-only contact.
    #[must_use]
    pub const fn tofu_state(&self) -> CredentialV2TofuState {
        self.tofu_state
    }

    /// Borrow the authenticated transition.
    #[must_use]
    pub const fn transition(&self) -> &CredentialV2Transition {
        self.claims.transition()
    }

    /// Borrow the digest of the authenticated signed offer core.
    #[must_use]
    pub const fn offer_core_digest(&self) -> &[u8; 32] {
        self.claims.offer_core_digest()
    }
}

/// Consumer adapter that completely recognises one signed offer body.
pub trait CredentialV2OfferParser: fmt::Debug + Send {
    /// Parse the exact unpadded body and return only bounded typed claims.
    fn parse_signed_offer(
        &mut self,
        body: &[u8],
    ) -> Result<CredentialV2IntentClaims, CredentialV2Error>;
}

/// Consumer verifier that can return only a closed verdict.
pub trait CredentialV2IntentVerifier: fmt::Debug + Send {
    /// Authenticate the immutable peer input against separate live authority.
    fn verify(
        &mut self,
        peer: &CredentialV2IntentInput,
        authority: &CredentialV2IntentAuthority,
    ) -> Result<(), CredentialV2Error>;
}

/// Recognise, cross-check, verify, and only then allocate one typed display.
pub fn recognise_credential_v2_intent(
    object: &CredentialV2Object,
    authority: &CredentialV2IntentAuthority,
    parser: &mut dyn CredentialV2OfferParser,
    verifier: &mut dyn CredentialV2IntentVerifier,
) -> Result<CredentialV2Display, CredentialV2Error> {
    if object.kind() != CredentialV2Kind::Offer {
        return Err(CredentialV2Error::Schema);
    }
    let claims = parser.parse_signed_offer(object.body())?;
    claims.validate().map_err(|_| CredentialV2Error::Profile)?;
    let intent_digest = credential_v2_intent_digest(*claims.offer_core_digest());
    if object.intent_digest() != &intent_digest {
        return Err(CredentialV2Error::Profile);
    }
    let peer = CredentialV2IntentInput {
        claims,
        intent_digest,
    };
    if peer.claims != authority.claims || peer.intent_digest != authority.intent_digest {
        return Err(CredentialV2Error::Profile);
    }
    verifier.verify(&peer, authority)?;
    Ok(CredentialV2Display {
        claims: authority.claims.clone(),
        tofu_state: authority.tofu_state,
    })
}

/// Derive the one credential/v2 intent digest from the signed offer-core digest.
#[must_use]
pub fn credential_v2_intent_digest(offer_core_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"selfsame credential/v2 intent\0");
    digest.update(offer_core_digest);
    digest.finalize().into()
}

pub(super) fn recognise_application_id(value: &str) -> Result<&str, CredentialV2Error> {
    if value.is_empty() || value.len() > MAX_APPLICATION_ID_OCTETS {
        return Err(CredentialV2Error::Schema);
    }
    let (origin, path) = split_https(value)?;
    if path.is_empty()
        || !path.starts_with('/')
        || path.strip_prefix('/').is_none_or(|rest| {
            rest.split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        })
        || !valid_path(path)
    {
        return Err(CredentialV2Error::Schema);
    }
    Ok(origin)
}

fn recognise_origin(value: &str, maximum: usize) -> Result<(), CredentialV2Error> {
    if value.is_empty() || value.len() > maximum {
        return Err(CredentialV2Error::Origin);
    }
    let (origin, path) = split_https(value)?;
    if origin != value || !path.is_empty() {
        return Err(CredentialV2Error::Origin);
    }
    Ok(())
}

fn split_https(value: &str) -> Result<(&str, &str), CredentialV2Error> {
    if !value.is_ascii() || value.contains(['?', '#']) {
        return Err(CredentialV2Error::Origin);
    }
    let rest = value
        .strip_prefix("https://")
        .ok_or(CredentialV2Error::Origin)?;
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = rest.get(..authority_end).ok_or(CredentialV2Error::Origin)?;
    if authority.is_empty() || authority.contains('@') {
        return Err(CredentialV2Error::Origin);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !valid_host(host) || !port.is_none_or(valid_port) {
        return Err(CredentialV2Error::Origin);
    }
    let origin_len = "https://".len() + authority.len();
    let origin = value.get(..origin_len).ok_or(CredentialV2Error::Origin)?;
    let path = value.get(origin_len..).ok_or(CredentialV2Error::Origin)?;
    Ok((origin, path))
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes().first() != Some(&b'-')
            && label.as_bytes().last() != Some(&b'-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) && labels
        .last()
        .is_some_and(|label| !label.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_port(port: &str) -> bool {
    if port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    port.parse::<u16>()
        .is_ok_and(|number| number != 0 && number != 443)
}

fn valid_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(pair) = bytes.get(index + 1..index + 3) else {
                return false;
            };
            if !pair
                .iter()
                .all(|value| value.is_ascii_digit() || (b'A'..=b'F').contains(value))
            {
                return false;
            }
            let decoded = (hex(pair[0]) << 4) | hex(pair[1]);
            if is_unreserved(decoded) {
                return false;
            }
            index += 3;
            continue;
        }
        if byte != b'/' && !is_pchar(byte) {
            return false;
        }
        index += 1;
    }
    true
}

const fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

const fn is_unreserved(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')
}

const fn is_pchar(value: u8) -> bool {
    is_unreserved(value)
        || matches!(
            value,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn valid_legacy_handle(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('@') else {
        return false;
    };
    (1..=32).contains(&rest.len())
        && rest.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_room(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('@') else {
        return false;
    };
    !rest.is_empty()
        && value.is_ascii()
        && value.len() <= MAX_ROOM_OCTETS
        && rest.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-'
                        | b'.'
                        | b'/'
                        | b'!'
                        | b'?'
                        | b'+'
                        | b'*'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'@'
                )
        })
}

fn room_array_octets(rooms: &[String]) -> usize {
    2 + rooms.iter().map(|room| room.len() + 2).sum::<usize>() + rooms.len().saturating_sub(1)
}

const fn is_base58btc(value: u8) -> bool {
    matches!(value, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}
