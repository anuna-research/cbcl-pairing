use super::{decode_canonical, field, map_entries, uint, CredentialV2Error};
use ciborium::Value;
use sha2::{Digest, Sha256};

/// Fixed credential/v2 control-body field capacity.
pub const CONTROL_PADDING_BYTES: usize = 4_096;
/// Fixed credential/v2 large-body field capacity.
pub const LARGE_PADDING_BYTES: usize = 64_512;
const MAX_CONTROL_BODY: usize = 2_048;
const MAX_LARGE_BODY: usize = 62_000;

/// Closed credential/v2 object-kind assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2Kind {
    /// Allocator offer.
    Offer,
    /// Claimant preliminary approval.
    IntentApprove,
    /// Claimant preliminary decline.
    IntentDecline,
    /// Claimant preparation result.
    Preparation,
    /// Allocator comparison confirmation.
    ComparisonConfirmed,
    /// Allocator binding confirmation.
    BindingConfirmed,
    /// Either role's pre-payload refusal.
    Refusal,
    /// Claimant final approval.
    FinalApprove,
    /// Claimant final decline.
    FinalDecline,
    /// Claimant credential payload.
    Payload,
    /// Allocator authenticated receipt.
    Receipt,
}

impl CredentialV2Kind {
    /// Every kind in its fixed numeric assignment order.
    pub const ALL: [Self; 11] = [
        Self::Offer,
        Self::IntentApprove,
        Self::IntentDecline,
        Self::Preparation,
        Self::ComparisonConfirmed,
        Self::BindingConfirmed,
        Self::Refusal,
        Self::FinalApprove,
        Self::FinalDecline,
        Self::Payload,
        Self::Receipt,
    ];

    /// Return the exact protocol integer.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Offer => 0,
            Self::IntentApprove => 1,
            Self::IntentDecline => 2,
            Self::Preparation => 3,
            Self::ComparisonConfirmed => 4,
            Self::BindingConfirmed => 5,
            Self::Refusal => 6,
            Self::FinalApprove => 7,
            Self::FinalDecline => 8,
            Self::Payload => 9,
            Self::Receipt => 10,
        }
    }

    /// Report whether this kind uses the fixed large arm.
    #[must_use]
    pub const fn is_large(self) -> bool {
        matches!(self, Self::Offer | Self::Payload | Self::Receipt)
    }

    pub(super) fn from_number(value: u64) -> Result<Self, CredentialV2Error> {
        Self::ALL
            .get(usize::try_from(value).map_err(|_| CredentialV2Error::Schema)?)
            .copied()
            .ok_or(CredentialV2Error::Schema)
    }
}

/// One fully recognised padded credential/v2 application object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2Object {
    kind: CredentialV2Kind,
    intent_digest: [u8; 32],
    body: Vec<u8>,
    bytes: Vec<u8>,
    content_hash: [u8; 32],
}

impl CredentialV2Object {
    /// Construct one exact padded object from a closed kind and logical body.
    pub fn new(
        kind: CredentialV2Kind,
        intent_digest: [u8; 32],
        body: Vec<u8>,
    ) -> Result<Self, CredentialV2Error> {
        validate_body(kind, body.len())?;
        let capacity = capacity(kind);
        let mut padded = vec![0_u8; capacity];
        padded[..body.len()].copy_from_slice(&body);
        let value = Value::Map(vec![
            (Value::Integer(0.into()), Value::Integer(2.into())),
            (
                Value::Integer(1.into()),
                Value::Integer(u64::from(kind.number()).into()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(intent_digest.to_vec()),
            ),
            (
                Value::Integer(3.into()),
                Value::Integer(
                    u64::try_from(body.len())
                        .map_err(|_| CredentialV2Error::Size)?
                        .into(),
                ),
            ),
            (Value::Integer(4.into()), Value::Bytes(padded)),
        ]);
        let bytes = cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::Schema)?;
        let content_hash = Sha256::digest(&bytes).into();
        Ok(Self {
            kind,
            intent_digest,
            body,
            bytes,
            content_hash,
        })
    }

    /// Return the closed object kind.
    #[must_use]
    pub const fn kind(&self) -> CredentialV2Kind {
        self.kind
    }

    /// Return the common intent digest.
    #[must_use]
    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    /// Borrow the unpadded logical body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrow the exact canonical padded object bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the object and return its exact canonical bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the fixed size of field 4 for this object's arm.
    #[must_use]
    pub const fn padding_len(&self) -> usize {
        capacity(self.kind)
    }

    /// Return SHA-256 over the exact canonical padded object.
    #[must_use]
    pub const fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }
}

/// Recognise one complete deterministic padded credential/v2 object.
pub fn decode_object(input: &[u8]) -> Result<CredentialV2Object, CredentialV2Error> {
    let value = decode_canonical(input)?;
    let entries = map_entries(&value)?;
    if entries.len() != 5 || uint(field(entries, &Value::Integer(0.into()))?)? != 2 {
        return Err(CredentialV2Error::Schema);
    }
    let kind = CredentialV2Kind::from_number(uint(field(entries, &Value::Integer(1.into()))?)?)?;
    let intent_digest = super::fixed_bytes(field(entries, &Value::Integer(2.into()))?)?;
    let body_len = usize::try_from(uint(field(entries, &Value::Integer(3.into()))?)?)
        .map_err(|_| CredentialV2Error::Size)?;
    validate_body(kind, body_len)?;
    let padded = field(entries, &Value::Integer(4.into()))?
        .as_bytes()
        .ok_or(CredentialV2Error::Schema)?;
    if padded.len() != capacity(kind) || padded[body_len..].iter().any(|byte| *byte != 0) {
        return Err(CredentialV2Error::Schema);
    }
    let object = CredentialV2Object::new(kind, intent_digest, padded[..body_len].to_vec())?;
    if object.as_bytes() != input {
        return Err(CredentialV2Error::NonDeterministic);
    }
    Ok(object)
}

const fn capacity(kind: CredentialV2Kind) -> usize {
    if kind.is_large() {
        LARGE_PADDING_BYTES
    } else {
        CONTROL_PADDING_BYTES
    }
}

fn validate_body(kind: CredentialV2Kind, length: usize) -> Result<(), CredentialV2Error> {
    let maximum = if kind.is_large() {
        MAX_LARGE_BODY
    } else {
        MAX_CONTROL_BODY
    };
    if length == 0 || length > maximum {
        Err(CredentialV2Error::Size)
    } else {
        Ok(())
    }
}
