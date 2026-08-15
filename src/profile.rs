//! Endpoint-local application profile contracts.
//!
//! Profiles recognise application claims and payloads after the shared pairing
//! core has established the channel. They are never consulted by the relay.

use crate::wire::{ApplicationPayload, Locator, PairingIntent};
use std::fmt;

/// Agent pairing application identifier.
pub const AGENT_APPLICATION: &str = "anuna.io/agent/v1";
/// Agent pairing grant payload identifier.
pub const AGENT_PAYLOAD: &str = "anuna.io/agent-grant/v1";
/// Credential transfer application identifier.
pub const CREDENTIAL_APPLICATION: &str = "anuna.io/credential/v1";
/// Account credential payload identifier.
pub const CREDENTIAL_PAYLOAD: &str = "anuna.io/account-credential/v1";
/// Conformance-only synthetic application identifier.
pub const SYNTHETIC_APPLICATION: &str = "example.test/synthetic/v1";
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayField {
    /// Stable field label.
    pub label: &'static str,
    /// Fully recognised display value.
    pub value: String,
    /// Whether the value is an unverified holder claim.
    pub claimed_by_secret_holder: bool,
}

/// Fully profile-recognised intent safe to present for approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayIntent {
    /// Exact application identifier.
    pub application: String,
    /// Exact profile action.
    pub action: String,
    /// Human-readable authority summary.
    pub authority_summary: String,
    /// Profile-defined recognised fields.
    pub fields: Vec<DisplayField>,
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
    /// Construct a recognised intent from display fields and canonical binding
    /// material. The material itself is not retained.
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
    /// Temporary behavioural Red Gate sentinel.
    NotImplemented,
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

/// Endpoint-local application contract used by the shared reducer.
pub trait ApplicationProfile: fmt::Debug + Send {
    /// Describe carrier, approval, payload, and verifier semantics.
    fn descriptor(&self) -> &ProfileDescriptor;

    /// Fully recognise an intent before any display or approval affordance.
    fn recognise_intent(&self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError>;

    /// Recognise and authorize an approval-gated payload.
    fn authorize_payload(
        &mut self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<AuthorisedGrant, ProfileError>;
}

/// Built-in agent pairing profile.
#[derive(Debug)]
pub struct AgentProfile {
    descriptor: ProfileDescriptor,
}

impl AgentProfile {
    /// Construct the fixed version-1 agent profile.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptor: agent_descriptor(),
        }
    }
}

impl Default for AgentProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationProfile for AgentProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn recognise_intent(&self, _intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        Err(ProfileError::NotImplemented)
    }

    fn authorize_payload(
        &mut self,
        _binding: &ProfileBinding,
        _payload: &ApplicationPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        Err(ProfileError::NotImplemented)
    }
}

/// Built-in account credential transfer profile.
#[derive(Debug)]
pub struct CredentialProfile {
    descriptor: ProfileDescriptor,
}

impl CredentialProfile {
    /// Construct the fixed version-1 credential profile.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptor: credential_descriptor(),
        }
    }
}

impl Default for CredentialProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationProfile for CredentialProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }

    fn recognise_intent(&self, _intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        Err(ProfileError::NotImplemented)
    }

    fn authorize_payload(
        &mut self,
        _binding: &ProfileBinding,
        _payload: &ApplicationPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        Err(ProfileError::NotImplemented)
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

    fn recognise_intent(&self, _intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        Err(ProfileError::NotImplemented)
    }

    fn authorize_payload(
        &mut self,
        _binding: &ProfileBinding,
        _payload: &ApplicationPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        let _ = self.authorize;
        Err(ProfileError::NotImplemented)
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
