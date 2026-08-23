use super::{
    bytes_field, decode_canonical, display::recognise_application_id, map_entries, optional_field,
    text_field, uint_field, CredentialV2Error,
};
use crate::wire::ClaimToken;
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;
use zeroize::Zeroizing;

const PROFILE: &str = "anuna.io/credential/v2";

/// Inputs for one allocator-created credential/v2 machine carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2CarrierInput {
    /// Canonical HTTPS application identifier.
    pub application_context: String,
    /// Canonical HTTPS blind-relay origin.
    pub relay_origin: String,
    /// Allocator-created direct mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Sole ceremony identifier for every downstream binding.
    pub carrier_ceremony_id: [u8; 32],
    /// Fresh carrier nonce.
    pub carrier_nonce: [u8; 32],
    /// Commitment to the separate claim presence token.
    pub claim_commitment: [u8; 32],
    /// Exact absolute relay expiry returned by allocation.
    pub relay_expires_at: u64,
    /// Optional expected allocator ceremony-key digest.
    pub expected_allocator_key: Option<[u8; 32]>,
}

/// Fully recognised credential/v2 machine carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2Carrier(CredentialV2CarrierInput);

impl CredentialV2Carrier {
    /// Validate and construct one carrier without any presence secret.
    pub fn new(input: CredentialV2CarrierInput) -> Result<Self, CredentialV2Error> {
        recognise_application_id(&input.application_context)?;
        validate_origin(&input.relay_origin, 272)?;
        let carrier = Self(input);
        encode_carrier(&carrier)?;
        Ok(carrier)
    }

    /// Borrow the authenticated application context named by the carrier.
    #[must_use]
    pub fn application_context(&self) -> &str {
        &self.0.application_context
    }

    /// Borrow the exact relay origin.
    #[must_use]
    pub fn relay_origin(&self) -> &str {
        &self.0.relay_origin
    }

    /// Return the direct mailbox identifier.
    #[must_use]
    pub const fn mailbox_id(&self) -> &[u8; 32] {
        &self.0.mailbox_id
    }

    /// Return the sole carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.0.carrier_ceremony_id
    }

    /// Return the fresh carrier nonce.
    #[must_use]
    pub const fn carrier_nonce(&self) -> &[u8; 32] {
        &self.0.carrier_nonce
    }

    /// Return the mailbox claim commitment.
    #[must_use]
    pub const fn claim_commitment(&self) -> &[u8; 32] {
        &self.0.claim_commitment
    }

    /// Return the immutable relay expiry.
    #[must_use]
    pub const fn relay_expires_at(&self) -> u64 {
        self.0.relay_expires_at
    }

    /// Return the optional expected allocator key digest.
    #[must_use]
    pub const fn expected_allocator_key(&self) -> Option<&[u8; 32]> {
        self.0.expected_allocator_key.as_ref()
    }

    /// Hash the exact canonical carrier bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = encode_carrier(self).expect("validated carrier always re-encodes");
        Sha256::digest(bytes).into()
    }
}

/// Human-presence secrets supplied separately from the machine carrier.
pub struct CredentialV2Presence {
    cpace_secret: Zeroizing<[u8; 16]>,
    claim_token: Option<ClaimToken>,
}

impl CredentialV2Presence {
    /// Construct separate CPace and claim-presence inputs.
    #[must_use]
    pub fn new(cpace_secret: [u8; 16], claim_token: [u8; 16]) -> Self {
        Self {
            cpace_secret: Zeroizing::new(cpace_secret),
            claim_token: Some(ClaimToken::new(claim_token)),
        }
    }

    /// Borrow the CPace password-related secret.
    #[must_use]
    pub fn cpace_secret(&self) -> &[u8; 16] {
        &self.cpace_secret
    }

    /// Consume the claim token once for protected mailbox admission.
    pub fn take_claim_token(&mut self) -> Result<ClaimToken, CredentialV2Error> {
        self.claim_token.take().ok_or(CredentialV2Error::Terminal)
    }

    pub(super) fn checkpoint_parts(&self) -> (&[u8; 16], Option<&ClaimToken>) {
        (&self.cpace_secret, self.claim_token.as_ref())
    }

    pub(super) fn from_checkpoint(cpace_secret: [u8; 16], claim_token: Option<[u8; 16]>) -> Self {
        Self {
            cpace_secret: Zeroizing::new(cpace_secret),
            claim_token: claim_token.map(ClaimToken::new),
        }
    }
}

impl fmt::Debug for CredentialV2Presence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialV2Presence([REDACTED])")
    }
}

/// Encode one credential/v2 carrier with deterministic CBOR.
pub fn encode_carrier(carrier: &CredentialV2Carrier) -> Result<Vec<u8>, CredentialV2Error> {
    let input = &carrier.0;
    recognise_application_id(&input.application_context)?;
    validate_origin(&input.relay_origin, 272)?;
    let mut entries = vec![
        (Value::Text("version".into()), Value::Integer(2.into())),
        (Value::Text("profile".into()), Value::Text(PROFILE.into())),
        (
            Value::Text("application-context".into()),
            Value::Text(input.application_context.clone()),
        ),
        (
            Value::Text("profile-version".into()),
            Value::Integer(2.into()),
        ),
        (
            Value::Text("relay-origin".into()),
            Value::Text(input.relay_origin.clone()),
        ),
        (
            Value::Text("locator".into()),
            Value::Bytes(input.mailbox_id.to_vec()),
        ),
        (
            Value::Text("carrier-ceremony-id".into()),
            Value::Bytes(input.carrier_ceremony_id.to_vec()),
        ),
        (
            Value::Text("carrier-nonce".into()),
            Value::Bytes(input.carrier_nonce.to_vec()),
        ),
        (
            Value::Text("claim-commitment".into()),
            Value::Bytes(input.claim_commitment.to_vec()),
        ),
        (
            Value::Text("relay-expires-at".into()),
            Value::Integer(input.relay_expires_at.into()),
        ),
    ];
    if let Some(key) = input.expected_allocator_key {
        entries.push((
            Value::Text("expected-allocator-key".into()),
            Value::Bytes(key.to_vec()),
        ));
    }
    cbor2::to_canonical_vec(&Value::Map(entries)).map_err(|_| CredentialV2Error::Schema)
}

/// Recognise one complete deterministic credential/v2 carrier.
pub fn decode_carrier(input: &[u8]) -> Result<CredentialV2Carrier, CredentialV2Error> {
    let value = decode_canonical(input)?;
    let entries = map_entries(&value)?;
    let expected_len = if optional_field(entries, "expected-allocator-key").is_some() {
        11
    } else {
        10
    };
    if entries.len() != expected_len
        || uint_field(entries, "version")? != 2
        || text_field(entries, "profile")? != PROFILE
        || uint_field(entries, "profile-version")? != 2
    {
        return Err(CredentialV2Error::Schema);
    }
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: text_field(entries, "application-context")?.into(),
        relay_origin: text_field(entries, "relay-origin")?.into(),
        mailbox_id: bytes_field(entries, "locator")?,
        carrier_ceremony_id: bytes_field(entries, "carrier-ceremony-id")?,
        carrier_nonce: bytes_field(entries, "carrier-nonce")?,
        claim_commitment: bytes_field(entries, "claim-commitment")?,
        relay_expires_at: uint_field(entries, "relay-expires-at")?,
        expected_allocator_key: optional_field(entries, "expected-allocator-key")
            .map(super::fixed_bytes)
            .transpose()?,
    })?;
    if encode_carrier(&carrier)? != input {
        return Err(CredentialV2Error::NonDeterministic);
    }
    Ok(carrier)
}

fn validate_origin(value: &str, maximum: usize) -> Result<(), CredentialV2Error> {
    if value.is_empty() || value.len() > maximum || !value.is_ascii() {
        return Err(CredentialV2Error::Origin);
    }
    let parsed = Url::parse(value).map_err(|_| CredentialV2Error::Origin)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.origin().ascii_serialization() != value
    {
        return Err(CredentialV2Error::Origin);
    }
    Ok(())
}
