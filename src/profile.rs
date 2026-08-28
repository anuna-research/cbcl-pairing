//! Endpoint-local application profile contracts.
//!
//! Profiles recognise invitation carriage, claims, displayed intent, payload
//! binding, and grant-verifier inputs. They are injected into an endpoint and
//! are never registered with or consulted by the relay.

use crate::wire::{ApplicationPayload, Invitation, Locator, PairingIntent};
use bip39::Language;
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::{fmt, io::Cursor};
use url::Url;

/// Agent pairing application identifier.
pub const AGENT_APPLICATION: &str = "anuna.io/agent/v1";
/// Exact agent intent action.
pub const AGENT_ACTION: &str = "pair-agent";
/// Agent pairing grant payload identifier.
pub const AGENT_PAYLOAD: &str = "anuna.io/agent-grant/v1";
/// Credential transfer application identifier.
pub const CREDENTIAL_APPLICATION: &str = "anuna.io/credential/v1";
/// Exact credential intent action.
pub const CREDENTIAL_ACTION: &str = "transfer-credential";
/// Account credential payload identifier.
pub const CREDENTIAL_PAYLOAD: &str = "anuna.io/account-credential/v1";
/// Conformance-only synthetic application identifier.
pub const SYNTHETIC_APPLICATION: &str = "example.test/synthetic/v1";
/// Exact synthetic intent action.
pub const SYNTHETIC_ACTION: &str = "exercise-profile";
/// Conformance-only synthetic grant payload identifier.
pub const SYNTHETIC_PAYLOAD: &str = "example.test/synthetic-grant/v1";

/// Carrier and entropy requirements owned by an application profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarrierContract {
    /// Human-readable carrier family.
    pub carrier: &'static str,
    /// Required invitation locator form.
    pub locator: LocatorKind,
    /// Minimum entropy supplied by the carrier secret.
    pub minimum_entropy_bits: u16,
}

/// Locator form required by a profile carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocatorKind {
    /// Direct random mailbox identifier.
    Direct,
    /// Relay allocated numeric nameplate.
    Nameplate,
}

impl LocatorKind {
    /// Test whether a recognised invitation locator has this form.
    #[must_use]
    pub fn matches(self, locator: &Locator) -> bool {
        matches!(
            (self, locator),
            (Self::Direct, Locator::Direct(_)) | (Self::Nameplate, Locator::Nameplate(_))
        )
    }
}

/// Complete endpoint-side application contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDescriptor {
    /// Exact application identifier bound into the invitation and transcript.
    pub application: &'static str,
    /// Exact accepted payload type.
    pub payload_type: &'static str,
    /// Carrier and entropy contract.
    pub carrier: CarrierContract,
    /// Authority that may approve the displayed intent.
    pub approval_authority: &'static str,
    /// Named grant-verifier contract.
    pub grant_verifier: &'static str,
}

/// One human-displayable field produced only after full profile recognition.
///
/// External callers cannot fabricate a recognised field:
///
/// ```compile_fail
/// use cbcl_pairing::profile::DisplayField;
/// let _ = DisplayField {
///     label: "forged",
///     value: "peer text".into(),
///     claimed_by_secret_holder: false,
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DisplayField {
    /// Stable field label.
    label: &'static str,
    /// Fully recognised display value.
    value: String,
    /// Whether the value is an unverified holder claim.
    claimed_by_secret_holder: bool,
}

impl DisplayField {
    /// Borrow the stable field label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// Borrow the fully recognised display value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Report whether this legacy field is an unverified holder claim.
    #[must_use]
    pub const fn claimed_by_secret_holder(&self) -> bool {
        self.claimed_by_secret_holder
    }
}

/// Fully profile-recognised intent safe to present for approval.
///
/// External callers cannot replace its recognised display body:
///
/// ```compile_fail
/// use cbcl_pairing::profile::DisplayIntent;
/// let _ = DisplayIntent {
///     application: "forged".into(),
///     action: "approve".into(),
///     authority_summary: "unchecked".into(),
///     fields: Vec::new(),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DisplayIntent {
    /// Exact application identifier.
    application: String,
    /// Exact profile action.
    action: String,
    /// Human-readable authority summary.
    authority_summary: String,
    /// Profile-defined recognised fields.
    fields: Vec<DisplayField>,
}

impl DisplayIntent {
    /// Borrow the exact legacy application identifier.
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Borrow the exact legacy profile action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Borrow the recognised legacy authority summary.
    #[must_use]
    pub fn authority_summary(&self) -> &str {
        &self.authority_summary
    }

    /// Borrow the ordered recognised legacy fields.
    #[must_use]
    pub fn fields(&self) -> &[DisplayField] {
        &self.fields
    }
}

/// Opaque, non-plaintext binding retained after intent display.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileBinding([u8; 32]);

/// Result of fully recognising one profile intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileIntent {
    display: DisplayIntent,
    binding: ProfileBinding,
}

impl ProfileIntent {
    /// Construct a recognised intent from display fields and a digest over the
    /// profile's canonical binding material. The plaintext material is not
    /// retained by the shared endpoint.
    #[must_use]
    pub fn new(display: DisplayIntent, binding: [u8; 32]) -> Self {
        Self {
            display,
            binding: ProfileBinding(binding),
        }
    }

    /// Split display data from the opaque retained binding.
    #[must_use]
    pub fn into_parts(self) -> (DisplayIntent, ProfileBinding) {
        (self.display, self.binding)
    }
}

/// Fully recognised payload input passed to an application grant verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecognisedPayload {
    application: String,
    payload_type: String,
    body: Vec<u8>,
}

impl RecognisedPayload {
    fn grant(self) -> AuthorisedGrant {
        AuthorisedGrant {
            application: self.application,
            payload_type: self.payload_type,
            body: self.body,
        }
    }
}

/// Application grant released only after pairing approval and profile checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorisedGrant {
    /// Application profile that authorised the grant.
    pub application: String,
    /// Fully recognised payload type.
    pub payload_type: String,
    /// Profile-recognised grant body.
    pub body: Vec<u8>,
}

/// Closed profile failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// Invitation application, carrier, or secret encoding is invalid.
    InvalidInvitation,
    /// Invitation and profile application identifiers differ.
    WrongApplication,
    /// The action is not defined by the selected profile.
    InvalidAction,
    /// A claim body is malformed or semantically invalid.
    InvalidClaim,
    /// The payload type is not defined by the selected profile.
    InvalidPayloadType,
    /// The payload is malformed or does not bind the recognised intent.
    InvalidPayload,
    /// The profile's grant verifier denied the payload.
    Unauthorized,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProfileError {}

/// Application-owned verifier for an already recognised and intent-bound
/// payload. Agent and credential consumers inject their authoritative verifier
/// rather than teaching the shared pairing crate application grant semantics.
pub trait GrantVerifier: fmt::Debug + Send {
    /// Accept or deny one exact recognised verifier input.
    fn verify(&mut self, payload: &RecognisedPayload) -> Result<(), ProfileError>;
}

/// Endpoint-local application contract used by the shared reducer.
pub trait ApplicationProfile: fmt::Debug + Send {
    /// Describe carrier, approval, payload, and verifier semantics.
    fn descriptor(&self) -> &ProfileDescriptor;

    /// Fully recognise the profile-owned invitation carrier contract.
    fn recognise_invitation(&self, invitation: &Invitation) -> Result<(), ProfileError>;

    /// Fully recognise an intent before any display or approval affordance.
    fn recognise_intent(&mut self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError>;

    /// Recognise a payload and its binding without invoking the grant verifier.
    fn recognise_payload(
        &self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<RecognisedPayload, ProfileError>;

    /// Invoke the authoritative verifier for one already pairing-gated payload.
    fn authorize_payload(
        &mut self,
        payload: RecognisedPayload,
    ) -> Result<AuthorisedGrant, ProfileError>;
}

/// Fields split across the two agent intent claim bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIntentClaims {
    /// Pairing channel presented to the approving person.
    pub channel: String,
    /// Principal claimed by the invitation holder.
    pub claimed_principal: String,
    /// Agent handle claimed by the invitation holder.
    pub agent_handle: String,
    /// Requested application grant.
    pub requested_grant: String,
}

impl AgentIntentClaims {
    /// Encode the allocator and claimant claim bodies as deterministic CBOR.
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        validate_agent_claims(self)?;
        Ok((
            encode_map(vec![
                ("principal", Value::Text(self.claimed_principal.clone())),
                ("agent-handle", Value::Text(self.agent_handle.clone())),
                ("requested-grant", Value::Text(self.requested_grant.clone())),
            ])?,
            encode_map(vec![("channel", Value::Text(self.channel.clone()))])?,
        ))
    }
}

/// Fully typed agent grant body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentGrant {
    /// Principal bound to the approved intent.
    pub claimed_principal: String,
    /// Agent handle bound to the approved intent.
    pub agent_handle: String,
    /// Requested grant bound to the approved intent.
    pub requested_grant: String,
    /// Opaque SPEC-061 grant bytes.
    pub grant: Vec<u8>,
}

impl AgentGrant {
    /// Encode the grant body as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        validate_agent_texts(
            &self.claimed_principal,
            &self.agent_handle,
            &self.requested_grant,
        )?;
        bounded_bytes(&self.grant, 1, 63_000).map_err(|_| ProfileError::InvalidPayload)?;
        encode_map(vec![
            ("principal", Value::Text(self.claimed_principal.clone())),
            ("agent-handle", Value::Text(self.agent_handle.clone())),
            ("requested-grant", Value::Text(self.requested_grant.clone())),
            ("grant", Value::Bytes(self.grant.clone())),
        ])
        .map_err(|_| ProfileError::InvalidPayload)
    }
}

/// Fields split across the two credential intent claim bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialIntentClaims {
    /// Canonical application identifier receiving the credential.
    pub application_id: String,
    /// Canonical HTTPS origin receiving the credential.
    pub origin: String,
    /// Requested account scope.
    pub scope: String,
    /// Recipient claimed by the invitation holder.
    pub recipient: String,
}

impl CredentialIntentClaims {
    /// Encode the allocator and claimant claim bodies as deterministic CBOR.
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        validate_credential_claims(self)?;
        Ok((
            encode_map(vec![
                ("application-id", Value::Text(self.application_id.clone())),
                ("origin", Value::Text(self.origin.clone())),
                ("scope", Value::Text(self.scope.clone())),
            ])?,
            encode_map(vec![("recipient", Value::Text(self.recipient.clone()))])?,
        ))
    }
}

/// Fully typed account credential payload body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialGrant {
    /// Application identifier bound to the approved intent.
    pub application_id: String,
    /// HTTPS origin bound to the approved intent.
    pub origin: String,
    /// Scope bound to the approved intent.
    pub scope: String,
    /// Recipient bound to the approved intent.
    pub recipient: String,
    /// Opaque SPEC-004/PROTO-004 credential bytes.
    pub credential: Vec<u8>,
}

impl CredentialGrant {
    /// Encode the credential body as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        validate_credential_claims(&CredentialIntentClaims {
            application_id: self.application_id.clone(),
            origin: self.origin.clone(),
            scope: self.scope.clone(),
            recipient: self.recipient.clone(),
        })?;
        bounded_bytes(&self.credential, 1, 62_000).map_err(|_| ProfileError::InvalidPayload)?;
        encode_map(vec![
            ("application-id", Value::Text(self.application_id.clone())),
            ("origin", Value::Text(self.origin.clone())),
            ("scope", Value::Text(self.scope.clone())),
            ("recipient", Value::Text(self.recipient.clone())),
            ("credential", Value::Bytes(self.credential.clone())),
        ])
        .map_err(|_| ProfileError::InvalidPayload)
    }
}

/// Fields split across the synthetic intent claim bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticIntentClaims {
    /// Synthetic subject.
    pub subject: String,
    /// Synthetic audience.
    pub audience: String,
}

impl SyntheticIntentClaims {
    /// Encode the allocator and claimant claim bodies as deterministic CBOR.
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        validate_synthetic_claims(self)?;
        Ok((
            encode_map(vec![("subject", Value::Text(self.subject.clone()))])?,
            encode_map(vec![("audience", Value::Text(self.audience.clone()))])?,
        ))
    }
}

/// Fully typed synthetic payload body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticGrant {
    /// Subject bound to the approved intent.
    pub subject: String,
    /// Audience bound to the approved intent.
    pub audience: String,
    /// Opaque synthetic grant bytes.
    pub grant: Vec<u8>,
}

impl SyntheticGrant {
    /// Encode the synthetic grant as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        validate_synthetic_claims(&SyntheticIntentClaims {
            subject: self.subject.clone(),
            audience: self.audience.clone(),
        })?;
        bounded_bytes(&self.grant, 1, 63_000).map_err(|_| ProfileError::InvalidPayload)?;
        encode_map(vec![
            ("subject", Value::Text(self.subject.clone())),
            ("audience", Value::Text(self.audience.clone())),
            ("grant", Value::Bytes(self.grant.clone())),
        ])
        .map_err(|_| ProfileError::InvalidPayload)
    }
}

/// Encode two independently generated BIP-39 indices as four canonical
/// big-endian octets. Each index contributes 11 bits, for 22 total bits.
pub fn encode_agent_word_indices(first: u16, second: u16) -> Result<[u8; 4], ProfileError> {
    if first > 2047 || second > 2047 {
        return Err(ProfileError::InvalidInvitation);
    }
    let mut result = [0_u8; 4];
    result[..2].copy_from_slice(&first.to_be_bytes());
    result[2..].copy_from_slice(&second.to_be_bytes());
    Ok(result)
}

/// Generated two-word agent carrier under the pinned English BIP-39 list.
///
/// The value carries exactly two independent 11-bit indices. It is constructed
/// either from 22 shell-supplied CSPRNG bits or by recognising received words;
/// there is no API for choosing arbitrary indices as a new invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentWordPair {
    indices: [u16; 2],
    secret: [u8; 4],
}

impl AgentWordPair {
    /// Generate a carrier from three CSPRNG octets supplied by the effectful
    /// application shell. The low two surplus bits are discarded, leaving a
    /// uniform 22-bit value split into two independent 11-bit indices.
    #[must_use]
    pub fn from_csprng_octets(octets: [u8; 3]) -> Self {
        let value = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]) >> 2;
        let first = ((value >> 11) & 0x7ff) as u16;
        let second = (value & 0x7ff) as u16;
        Self {
            indices: [first, second],
            secret: encode_agent_word_indices(first, second)
                .expect("masked 11-bit indices are always valid"),
        }
    }

    /// Recognise two received words under the exact English BIP-39 list.
    pub fn recognise(first: &str, second: &str) -> Result<Self, ProfileError> {
        let language = Language::English;
        let first = language
            .find_word(first)
            .ok_or(ProfileError::InvalidInvitation)?;
        let second = language
            .find_word(second)
            .ok_or(ProfileError::InvalidInvitation)?;
        Ok(Self {
            indices: [first, second],
            secret: encode_agent_word_indices(first, second)?,
        })
    }

    /// Return the two exact English BIP-39 words for display.
    #[must_use]
    pub fn words(&self) -> [&'static str; 2] {
        let words = Language::English.word_list();
        [
            words[usize::from(self.indices[0])],
            words[usize::from(self.indices[1])],
        ]
    }

    /// Return the normative four-octet CPace `PRS` carrier encoding.
    #[must_use]
    pub const fn secret(&self) -> [u8; 4] {
        self.secret
    }

    /// Return both word-list indices for carrier integrations.
    #[must_use]
    pub const fn indices(&self) -> [u16; 2] {
        self.indices
    }
}

/// Built-in agent pairing profile with an application-supplied SPEC-061
/// verifier.
#[derive(Debug)]
pub struct AgentProfile {
    descriptor: ProfileDescriptor,
    verifier: Box<dyn GrantVerifier>,
}

impl AgentProfile {
    /// Construct the fixed version-1 agent profile.
    #[must_use]
    pub fn new(verifier: Box<dyn GrantVerifier>) -> Self {
        Self {
            descriptor: agent_descriptor(),
            verifier,
        }
    }
}

impl ApplicationProfile for AgentProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn recognise_invitation(&self, invitation: &Invitation) -> Result<(), ProfileError> {
        common_invitation(&self.descriptor, invitation)?;
        if invitation.secret.len() != 4 {
            return Err(ProfileError::InvalidInvitation);
        }
        let first = u16::from_be_bytes([invitation.secret[0], invitation.secret[1]]);
        let second = u16::from_be_bytes([invitation.secret[2], invitation.secret[3]]);
        encode_agent_word_indices(first, second)?;
        Ok(())
    }

    fn recognise_intent(&mut self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        common_intent(&self.descriptor, AGENT_ACTION, intent)?;
        let claims = decode_agent_claims(&intent.allocator_claim, &intent.claimant_claim)?;
        let binding = agent_binding(&claims)?;
        Ok(ProfileIntent::new(
            display_intent(
                intent,
                vec![
                    display("channel", claims.channel),
                    display("claimed principal", claims.claimed_principal),
                    display("agent handle", claims.agent_handle),
                    display("requested grant", claims.requested_grant),
                ],
            ),
            binding,
        ))
    }

    fn recognise_payload(
        &self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<RecognisedPayload, ProfileError> {
        payload_type(&self.descriptor, payload)?;
        let grant = decode_agent_grant(&payload.body)?;
        let claims = AgentIntentClaims {
            channel: String::new(),
            claimed_principal: grant.claimed_principal,
            agent_handle: grant.agent_handle,
            requested_grant: grant.requested_grant,
        };
        if agent_payload_binding(&claims)? != binding.0 {
            return Err(ProfileError::InvalidPayload);
        }
        Ok(recognised(&self.descriptor, payload))
    }

    fn authorize_payload(
        &mut self,
        payload: RecognisedPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        self.verifier.verify(&payload)?;
        Ok(payload.grant())
    }
}

/// Built-in account credential transfer profile with an application-supplied
/// SPEC-004/PROTO-004 verifier.
#[derive(Debug)]
pub struct CredentialProfile {
    descriptor: ProfileDescriptor,
    verifier: Box<dyn GrantVerifier>,
}

impl CredentialProfile {
    /// Construct the fixed version-1 credential profile.
    #[must_use]
    pub fn new(verifier: Box<dyn GrantVerifier>) -> Self {
        Self {
            descriptor: credential_descriptor(),
            verifier,
        }
    }
}

impl ApplicationProfile for CredentialProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn recognise_invitation(&self, invitation: &Invitation) -> Result<(), ProfileError> {
        common_invitation(&self.descriptor, invitation)?;
        if invitation.secret.len() != 16 {
            return Err(ProfileError::InvalidInvitation);
        }
        Ok(())
    }

    fn recognise_intent(&mut self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        common_intent(&self.descriptor, CREDENTIAL_ACTION, intent)?;
        let claims = decode_credential_claims(&intent.allocator_claim, &intent.claimant_claim)?;
        let binding = credential_binding(&claims)?;
        Ok(ProfileIntent::new(
            display_intent(
                intent,
                vec![
                    display("applicationId", claims.application_id),
                    display("HTTPS origin", claims.origin),
                    display("requested scope", claims.scope),
                    display("recipient", claims.recipient),
                ],
            ),
            binding,
        ))
    }

    fn recognise_payload(
        &self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<RecognisedPayload, ProfileError> {
        payload_type(&self.descriptor, payload)?;
        let grant = decode_credential_grant(&payload.body)?;
        let claims = CredentialIntentClaims {
            application_id: grant.application_id,
            origin: grant.origin,
            scope: grant.scope,
            recipient: grant.recipient,
        };
        if credential_binding(&claims)? != binding.0 {
            return Err(ProfileError::InvalidPayload);
        }
        Ok(recognised(&self.descriptor, payload))
    }

    fn authorize_payload(
        &mut self,
        payload: RecognisedPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        self.verifier.verify(&payload)?;
        Ok(payload.grant())
    }
}

/// Conformance profile proving that applications remain endpoint-local.
#[derive(Debug)]
pub struct SyntheticProfile {
    descriptor: ProfileDescriptor,
    authorize: bool,
}

impl SyntheticProfile {
    /// Construct a synthetic profile with a fixed verifier decision.
    #[must_use]
    pub fn new(authorize: bool) -> Self {
        Self {
            descriptor: synthetic_descriptor(),
            authorize,
        }
    }
}

impl ApplicationProfile for SyntheticProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn recognise_invitation(&self, invitation: &Invitation) -> Result<(), ProfileError> {
        common_invitation(&self.descriptor, invitation)?;
        if invitation.secret.len() != 16 {
            return Err(ProfileError::InvalidInvitation);
        }
        Ok(())
    }

    fn recognise_intent(&mut self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        common_intent(&self.descriptor, SYNTHETIC_ACTION, intent)?;
        let claims = decode_synthetic_claims(&intent.allocator_claim, &intent.claimant_claim)?;
        let binding = synthetic_binding(&claims)?;
        Ok(ProfileIntent::new(
            display_intent(
                intent,
                vec![
                    display("synthetic subject", claims.subject),
                    display("synthetic audience", claims.audience),
                ],
            ),
            binding,
        ))
    }

    fn recognise_payload(
        &self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<RecognisedPayload, ProfileError> {
        payload_type(&self.descriptor, payload)?;
        let grant = decode_synthetic_grant(&payload.body)?;
        let claims = SyntheticIntentClaims {
            subject: grant.subject,
            audience: grant.audience,
        };
        if synthetic_binding(&claims)? != binding.0 {
            return Err(ProfileError::InvalidPayload);
        }
        Ok(recognised(&self.descriptor, payload))
    }

    fn authorize_payload(
        &mut self,
        payload: RecognisedPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        if !self.authorize {
            return Err(ProfileError::Unauthorized);
        }
        Ok(payload.grant())
    }
}

fn agent_descriptor() -> ProfileDescriptor {
    ProfileDescriptor {
        application: AGENT_APPLICATION,
        payload_type: AGENT_PAYLOAD,
        carrier: CarrierContract {
            carrier: "configured relay + nameplate + two generated words",
            locator: LocatorKind::Nameplate,
            minimum_entropy_bits: 22,
        },
        approval_authority: "explicit person action",
        grant_verifier: "SPEC-061 bound pairing grant",
    }
}

fn credential_descriptor() -> ProfileDescriptor {
    ProfileDescriptor {
        application: CREDENTIAL_APPLICATION,
        payload_type: CREDENTIAL_PAYLOAD,
        carrier: CarrierContract {
            carrier: "QR, deep link, NFC, or OS handover",
            locator: LocatorKind::Direct,
            minimum_entropy_bits: 128,
        },
        approval_authority: "explicit person action",
        grant_verifier: "SPEC-004/PROTO-004 account credential",
    }
}

fn synthetic_descriptor() -> ProfileDescriptor {
    ProfileDescriptor {
        application: SYNTHETIC_APPLICATION,
        payload_type: SYNTHETIC_PAYLOAD,
        carrier: CarrierContract {
            carrier: "conformance octet carrier",
            locator: LocatorKind::Direct,
            minimum_entropy_bits: 128,
        },
        approval_authority: "explicit conformance decision",
        grant_verifier: "synthetic fixed-decision verifier",
    }
}

fn common_invitation(
    descriptor: &ProfileDescriptor,
    invitation: &Invitation,
) -> Result<(), ProfileError> {
    if invitation.application != descriptor.application {
        return Err(ProfileError::WrongApplication);
    }
    if !descriptor.carrier.locator.matches(&invitation.locator) {
        return Err(ProfileError::InvalidInvitation);
    }
    Ok(())
}

fn common_intent(
    descriptor: &ProfileDescriptor,
    action: &str,
    intent: &PairingIntent,
) -> Result<(), ProfileError> {
    if intent.application != descriptor.application {
        return Err(ProfileError::WrongApplication);
    }
    if intent.action != action {
        return Err(ProfileError::InvalidAction);
    }
    Ok(())
}

fn payload_type(
    descriptor: &ProfileDescriptor,
    payload: &ApplicationPayload,
) -> Result<(), ProfileError> {
    if payload.payload_type != descriptor.payload_type {
        return Err(ProfileError::InvalidPayloadType);
    }
    Ok(())
}

fn display_intent(intent: &PairingIntent, fields: Vec<DisplayField>) -> DisplayIntent {
    DisplayIntent {
        application: intent.application.clone(),
        action: intent.action.clone(),
        authority_summary: intent.authority_summary.clone(),
        fields,
    }
}

fn display(label: &'static str, value: String) -> DisplayField {
    DisplayField {
        label,
        value,
        claimed_by_secret_holder: true,
    }
}

fn recognised(descriptor: &ProfileDescriptor, payload: &ApplicationPayload) -> RecognisedPayload {
    RecognisedPayload {
        application: descriptor.application.into(),
        payload_type: payload.payload_type.clone(),
        body: payload.body.clone(),
    }
}

fn decode_agent_claims(
    allocator: &[u8],
    claimant: &[u8],
) -> Result<AgentIntentClaims, ProfileError> {
    let allocator = canonical_map(allocator, 3, ProfileError::InvalidClaim)?;
    let claimant = canonical_map(claimant, 1, ProfileError::InvalidClaim)?;
    let result = AgentIntentClaims {
        channel: text_field(&claimant, "channel", 64, ProfileError::InvalidClaim)?,
        claimed_principal: text_field(&allocator, "principal", 255, ProfileError::InvalidClaim)?,
        agent_handle: text_field(&allocator, "agent-handle", 128, ProfileError::InvalidClaim)?,
        requested_grant: text_field(
            &allocator,
            "requested-grant",
            128,
            ProfileError::InvalidClaim,
        )?,
    };
    validate_agent_claims(&result)?;
    Ok(result)
}

fn decode_agent_grant(input: &[u8]) -> Result<AgentGrant, ProfileError> {
    let fields = canonical_map(input, 4, ProfileError::InvalidPayload)?;
    let result = AgentGrant {
        claimed_principal: text_field(&fields, "principal", 255, ProfileError::InvalidPayload)?,
        agent_handle: text_field(&fields, "agent-handle", 128, ProfileError::InvalidPayload)?,
        requested_grant: text_field(
            &fields,
            "requested-grant",
            128,
            ProfileError::InvalidPayload,
        )?,
        grant: bytes_field(&fields, "grant", 63_000, ProfileError::InvalidPayload)?,
    };
    validate_agent_texts(
        &result.claimed_principal,
        &result.agent_handle,
        &result.requested_grant,
    )?;
    Ok(result)
}

fn validate_agent_claims(value: &AgentIntentClaims) -> Result<(), ProfileError> {
    bounded_text(&value.channel, 64).map_err(|_| ProfileError::InvalidClaim)?;
    validate_agent_texts(
        &value.claimed_principal,
        &value.agent_handle,
        &value.requested_grant,
    )
}

fn validate_agent_texts(
    principal: &str,
    handle: &str,
    requested_grant: &str,
) -> Result<(), ProfileError> {
    bounded_text(principal, 255).map_err(|_| ProfileError::InvalidClaim)?;
    bounded_text(handle, 128).map_err(|_| ProfileError::InvalidClaim)?;
    bounded_text(requested_grant, 128).map_err(|_| ProfileError::InvalidClaim)
}

fn agent_binding(value: &AgentIntentClaims) -> Result<[u8; 32], ProfileError> {
    binding(&[
        AGENT_APPLICATION,
        AGENT_ACTION,
        &value.claimed_principal,
        &value.agent_handle,
        &value.requested_grant,
    ])
}

fn agent_payload_binding(value: &AgentIntentClaims) -> Result<[u8; 32], ProfileError> {
    // Channel is deliberately display-only; the grant is bound to the three
    // identity/authority fields that it repeats.
    binding(&[
        AGENT_APPLICATION,
        AGENT_ACTION,
        &value.claimed_principal,
        &value.agent_handle,
        &value.requested_grant,
    ])
}

fn decode_credential_claims(
    allocator: &[u8],
    claimant: &[u8],
) -> Result<CredentialIntentClaims, ProfileError> {
    let allocator = canonical_map(allocator, 3, ProfileError::InvalidClaim)?;
    let claimant = canonical_map(claimant, 1, ProfileError::InvalidClaim)?;
    let result = CredentialIntentClaims {
        application_id: text_field(
            &allocator,
            "application-id",
            255,
            ProfileError::InvalidClaim,
        )?,
        origin: text_field(&allocator, "origin", 255, ProfileError::InvalidClaim)?,
        scope: text_field(&allocator, "scope", 255, ProfileError::InvalidClaim)?,
        recipient: text_field(&claimant, "recipient", 255, ProfileError::InvalidClaim)?,
    };
    validate_credential_claims(&result)?;
    Ok(result)
}

fn decode_credential_grant(input: &[u8]) -> Result<CredentialGrant, ProfileError> {
    let fields = canonical_map(input, 5, ProfileError::InvalidPayload)?;
    let result = CredentialGrant {
        application_id: text_field(&fields, "application-id", 255, ProfileError::InvalidPayload)?,
        origin: text_field(&fields, "origin", 255, ProfileError::InvalidPayload)?,
        scope: text_field(&fields, "scope", 255, ProfileError::InvalidPayload)?,
        recipient: text_field(&fields, "recipient", 255, ProfileError::InvalidPayload)?,
        credential: bytes_field(&fields, "credential", 62_000, ProfileError::InvalidPayload)?,
    };
    validate_credential_claims(&CredentialIntentClaims {
        application_id: result.application_id.clone(),
        origin: result.origin.clone(),
        scope: result.scope.clone(),
        recipient: result.recipient.clone(),
    })
    .map_err(|_| ProfileError::InvalidPayload)?;
    Ok(result)
}

fn validate_credential_claims(value: &CredentialIntentClaims) -> Result<(), ProfileError> {
    bounded_text(&value.application_id, 255).map_err(|_| ProfileError::InvalidClaim)?;
    canonical_https_origin(&value.origin).map_err(|_| ProfileError::InvalidClaim)?;
    bounded_text(&value.scope, 255).map_err(|_| ProfileError::InvalidClaim)?;
    bounded_text(&value.recipient, 255).map_err(|_| ProfileError::InvalidClaim)
}

fn credential_binding(value: &CredentialIntentClaims) -> Result<[u8; 32], ProfileError> {
    binding(&[
        CREDENTIAL_APPLICATION,
        CREDENTIAL_ACTION,
        &value.application_id,
        &value.origin,
        &value.scope,
        &value.recipient,
    ])
}

fn decode_synthetic_claims(
    allocator: &[u8],
    claimant: &[u8],
) -> Result<SyntheticIntentClaims, ProfileError> {
    let allocator = canonical_map(allocator, 1, ProfileError::InvalidClaim)?;
    let claimant = canonical_map(claimant, 1, ProfileError::InvalidClaim)?;
    let result = SyntheticIntentClaims {
        subject: text_field(&allocator, "subject", 128, ProfileError::InvalidClaim)?,
        audience: text_field(&claimant, "audience", 128, ProfileError::InvalidClaim)?,
    };
    validate_synthetic_claims(&result)?;
    Ok(result)
}

fn decode_synthetic_grant(input: &[u8]) -> Result<SyntheticGrant, ProfileError> {
    let fields = canonical_map(input, 3, ProfileError::InvalidPayload)?;
    let result = SyntheticGrant {
        subject: text_field(&fields, "subject", 128, ProfileError::InvalidPayload)?,
        audience: text_field(&fields, "audience", 128, ProfileError::InvalidPayload)?,
        grant: bytes_field(&fields, "grant", 63_000, ProfileError::InvalidPayload)?,
    };
    validate_synthetic_claims(&SyntheticIntentClaims {
        subject: result.subject.clone(),
        audience: result.audience.clone(),
    })
    .map_err(|_| ProfileError::InvalidPayload)?;
    Ok(result)
}

fn validate_synthetic_claims(value: &SyntheticIntentClaims) -> Result<(), ProfileError> {
    bounded_text(&value.subject, 128).map_err(|_| ProfileError::InvalidClaim)?;
    bounded_text(&value.audience, 128).map_err(|_| ProfileError::InvalidClaim)
}

fn synthetic_binding(value: &SyntheticIntentClaims) -> Result<[u8; 32], ProfileError> {
    binding(&[
        SYNTHETIC_APPLICATION,
        SYNTHETIC_ACTION,
        &value.subject,
        &value.audience,
    ])
}

fn binding(fields: &[&str]) -> Result<[u8; 32], ProfileError> {
    let value = Value::Array(
        fields
            .iter()
            .map(|field| Value::Text((*field).into()))
            .collect(),
    );
    let encoded = cbor2::to_canonical_vec(&value).map_err(|_| ProfileError::InvalidClaim)?;
    Ok(Sha256::digest(encoded).into())
}

fn encode_map(fields: Vec<(&str, Value)>) -> Result<Vec<u8>, ProfileError> {
    let value = Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::Text(key.into()), value))
            .collect(),
    );
    cbor2::to_canonical_vec(&value).map_err(|_| ProfileError::InvalidClaim)
}

fn canonical_map(
    input: &[u8],
    expected_fields: usize,
    error: ProfileError,
) -> Result<Vec<(Value, Value)>, ProfileError> {
    let mut cursor = Cursor::new(input);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| error)?;
    if cursor.position() != input.len() as u64 {
        return Err(error);
    }
    let canonical = cbor2::to_canonical_vec(&value).map_err(|_| error)?;
    if canonical != input {
        return Err(error);
    }
    let Value::Map(fields) = value else {
        return Err(error);
    };
    if fields.len() != expected_fields {
        return Err(error);
    }
    Ok(fields)
}

fn text_field(
    fields: &[(Value, Value)],
    name: &str,
    max: usize,
    error: ProfileError,
) -> Result<String, ProfileError> {
    let mut matches = fields.iter().filter(|(key, _)| key.as_text() == Some(name));
    let (_, value) = matches.next().ok_or(error)?;
    if matches.next().is_some() {
        return Err(error);
    }
    let text = value.as_text().ok_or(error)?;
    bounded_text(text, max).map_err(|_| error)?;
    Ok(text.into())
}

fn bytes_field(
    fields: &[(Value, Value)],
    name: &str,
    max: usize,
    error: ProfileError,
) -> Result<Vec<u8>, ProfileError> {
    let mut matches = fields.iter().filter(|(key, _)| key.as_text() == Some(name));
    let (_, value) = matches.next().ok_or(error)?;
    if matches.next().is_some() {
        return Err(error);
    }
    let bytes = value.as_bytes().ok_or(error)?;
    bounded_bytes(bytes, 1, max).map_err(|_| error)?;
    Ok(bytes.to_vec())
}

fn bounded_text(value: &str, max: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        Err(())
    } else {
        Ok(())
    }
}

fn bounded_bytes(value: &[u8], min: usize, max: usize) -> Result<(), ()> {
    if value.len() < min || value.len() > max {
        Err(())
    } else {
        Ok(())
    }
}

fn canonical_https_origin(value: &str) -> Result<(), ()> {
    let parsed = Url::parse(value).map_err(|_| ())?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(());
    }
    let host = parsed.host_str().ok_or(())?;
    let canonical = match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    };
    if value != canonical {
        return Err(());
    }
    Ok(())
}
