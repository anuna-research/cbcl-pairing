//! SPEC-080 CON-001: the claimant's account selection.
//!
//! The wallet is the only party that knows which accounts it already holds for
//! an application, and the allocator's Offer is the first object after the
//! channel is established, so the selection is its own object: sent by the
//! claimant exactly once, in phase `Begin`, before any Offer, and bound to the
//! carrier ceremony and the recognised application. It is a public selector,
//! never authority — acceptance still demands the account's DID.
//!
//! There is no intent digest yet when it is sent, so the object carries a fixed
//! pre-intent digest that the endpoint checks and never adopts as the
//! ceremony's intent.

use super::{
    decode_canonical, fixed_bytes, uint, CredentialV2Error, CredentialV2Kind, CredentialV2Object,
};
use ciborium::Value;
use sha2::{Digest, Sha256};

/// Exact domain string of the account-selection body.
pub const ACCOUNT_SELECT_DOMAIN: &str = "selfsame-account-select/v1";
const MAX_APPLICATION_ID: usize = 2_048;

/// The fixed pre-intent digest every AccountSelect object carries.
#[must_use]
pub fn account_select_intent_digest() -> [u8; 32] {
    Sha256::digest(b"cbcl-pairing credential/v2 account-select intent/v1").into()
}

/// One recognised account selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2AccountSelect {
    carrier_ceremony_id: [u8; 32],
    application_id: String,
    account_scope: Option<[u8; 32]>,
}

impl CredentialV2AccountSelect {
    /// Construct a selection for one ceremony and application. `None` selects a
    /// new account.
    pub fn new(
        carrier_ceremony_id: [u8; 32],
        application_id: &str,
        account_scope: Option<[u8; 32]>,
    ) -> Result<Self, CredentialV2Error> {
        if application_id.is_empty() || application_id.len() > MAX_APPLICATION_ID {
            return Err(CredentialV2Error::Schema);
        }
        Ok(Self {
            carrier_ceremony_id,
            application_id: application_id.into(),
            account_scope,
        })
    }

    /// Borrow the bound carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.carrier_ceremony_id
    }

    /// Borrow the canonical application identifier the selection is for.
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// The selected scope, or `None` for a new account.
    #[must_use]
    pub const fn account_scope(&self) -> Option<&[u8; 32]> {
        self.account_scope.as_ref()
    }

    /// Encode the exact canonical body:
    /// `[domain, carrier-ceremony-id, application-id, [0] / [1, scope]]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let selection = match self.account_scope {
            None => Value::Array(vec![Value::Integer(0.into())]),
            Some(scope) => {
                Value::Array(vec![Value::Integer(1.into()), Value::Bytes(scope.to_vec())])
            }
        };
        cbor2::to_canonical_vec(&Value::Array(vec![
            Value::Text(ACCOUNT_SELECT_DOMAIN.into()),
            Value::Bytes(self.carrier_ceremony_id.to_vec()),
            Value::Text(self.application_id.clone()),
            selection,
        ]))
        .expect("a fixed-shape array of text, bytes and small integers encodes")
    }

    /// Recognise one complete canonical body.
    pub fn decode(body: &[u8]) -> Result<Self, CredentialV2Error> {
        let value = decode_canonical(body)?;
        let Value::Array(members) = &value else {
            return Err(CredentialV2Error::Schema);
        };
        let [domain, ceremony, application, selection] = members.as_slice() else {
            return Err(CredentialV2Error::Schema);
        };
        if domain.as_text() != Some(ACCOUNT_SELECT_DOMAIN) {
            return Err(CredentialV2Error::Schema);
        }
        let carrier_ceremony_id = fixed_bytes(ceremony)?;
        let application_id = application.as_text().ok_or(CredentialV2Error::Schema)?;
        let Value::Array(selection) = selection else {
            return Err(CredentialV2Error::Schema);
        };
        let account_scope = match selection.as_slice() {
            [tag] if uint(tag)? == 0 => None,
            [tag, scope] if uint(tag)? == 1 => Some(fixed_bytes(scope)?),
            _ => return Err(CredentialV2Error::Schema),
        };
        Self::new(carrier_ceremony_id, application_id, account_scope)
    }

    /// Build the padded application object the claimant sends.
    pub fn object(&self) -> Result<CredentialV2Object, CredentialV2Error> {
        CredentialV2Object::new(
            CredentialV2Kind::AccountSelect,
            account_select_intent_digest(),
            self.encode(),
        )
    }

    /// Recognise a received object as this ceremony's selection for this
    /// application. Every mismatch is `Profile`; every shape failure is the
    /// codec's own error.
    pub fn recognise(
        object: &CredentialV2Object,
        carrier_ceremony_id: &[u8; 32],
        application_id: &str,
    ) -> Result<Self, CredentialV2Error> {
        if object.kind() != CredentialV2Kind::AccountSelect
            || object.intent_digest() != &account_select_intent_digest()
        {
            return Err(CredentialV2Error::Schema);
        }
        let selection = Self::decode(object.body())?;
        if &selection.carrier_ceremony_id != carrier_ceremony_id
            || selection.application_id != application_id
        {
            return Err(CredentialV2Error::Profile);
        }
        Ok(selection)
    }
}
