//! Canonical SPEC-072 CPace application inputs.

use crate::wire::{encode_invitation, Invitation, Locator, Side, SUITE_ID};
use ciborium::Value;
use std::fmt;

const CI_DOMAIN: &str = "cbcl-pairing-ci/v1";
const AD_DOMAIN: &str = "cbcl-pairing-ad/v1";

/// Exact deterministic CPace inputs derived from one invitation and resolved
/// mailbox identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingContext {
    channel_identifier: Vec<u8>,
    session_id: [u8; 32],
    associated_data: [Vec<u8>; 2],
}

impl PairingContext {
    /// Derive the normative `CI`, `sid`, `ADa`, and `ADb` values.
    pub fn derive(invitation: &Invitation, mailbox_id: [u8; 32]) -> Result<Self, ContextError> {
        encode_invitation(invitation).map_err(|_| ContextError::Invitation)?;
        if matches!(&invitation.locator, Locator::Direct(expected) if expected != &mailbox_id) {
            return Err(ContextError::MailboxMismatch);
        }
        let channel_identifier = canonical(&Value::Array(vec![
            Value::Text(CI_DOMAIN.into()),
            Value::Integer(1.into()),
            Value::Text(SUITE_ID.into()),
            Value::Text(invitation.application.clone()),
            Value::Text(invitation.relay_origin.clone()),
            Value::Bytes(mailbox_id.to_vec()),
            Value::Array(vec![
                Value::Text("allocator".into()),
                Value::Text("claimant".into()),
            ]),
        ]))?;
        let associated_data = [
            associated_data(Side::Allocator, invitation.expected_allocator_key.as_ref())?,
            associated_data(Side::Claimant, invitation.expected_claimant_key.as_ref())?,
        ];
        Ok(Self {
            channel_identifier,
            session_id: mailbox_id,
            associated_data,
        })
    }

    /// Borrow the exact deterministic CPace channel identifier.
    #[must_use]
    pub fn channel_identifier(&self) -> &[u8] {
        &self.channel_identifier
    }

    /// Borrow the exact 32-octet CPace session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Borrow one side's exact deterministic associated data.
    #[must_use]
    pub fn associated_data(&self, side: Side) -> &[u8] {
        &self.associated_data[match side {
            Side::Allocator => 0,
            Side::Claimant => 1,
        }]
    }
}

/// Canonical context construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// The typed invitation itself was not valid under the normative grammar.
    Invitation,
    /// A direct invitation named a different mailbox identifier.
    MailboxMismatch,
    /// Deterministic CBOR encoding failed.
    Encoding,
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ContextError {}

fn associated_data(side: Side, expected_key: Option<&[u8; 32]>) -> Result<Vec<u8>, ContextError> {
    canonical(&Value::Array(vec![
        Value::Text(AD_DOMAIN.into()),
        Value::Text(
            match side {
                Side::Allocator => "allocator",
                Side::Claimant => "claimant",
            }
            .into(),
        ),
        expected_key.map_or(Value::Null, |key| Value::Bytes(key.to_vec())),
    ]))
}

fn canonical(value: &Value) -> Result<Vec<u8>, ContextError> {
    cbor2::to_canonical_vec(value).map_err(|_| ContextError::Encoding)
}
