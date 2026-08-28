use super::{CredentialV2Carrier, CredentialV2Error, CredentialV2Presence};
use crate::{
    cpace::{self, CpaceMessage, CpaceState},
    wire::{Side, SUITE_ID},
};
use ciborium::Value;

const PROFILE: &str = "anuna.io/credential/v2";

/// Exact credential/v2 CPace inputs and secure-channel public context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialV2Context {
    channel_identifier: Vec<u8>,
    public_context: Vec<u8>,
    session_id: [u8; 32],
    carrier_ceremony_id: [u8; 32],
    carrier_digest: [u8; 32],
    associated_data: [Vec<u8>; 2],
}

impl CredentialV2Context {
    /// Derive every public byte from a recognised carrier and live profile.
    pub fn derive(
        carrier: &CredentialV2Carrier,
        profile_digest: [u8; 32],
    ) -> Result<Self, CredentialV2Error> {
        let carrier_digest = carrier.digest();
        let session_id = *carrier.mailbox_id();
        let carrier_ceremony_id = *carrier.carrier_ceremony_id();
        let channel_identifier = canonical(&Value::Array(vec![
            Value::Text("cbcl-pairing-ci/credential-v2".into()),
            Value::Integer(2.into()),
            Value::Text(SUITE_ID.into()),
            Value::Text(PROFILE.into()),
            Value::Text(carrier.application_context().into()),
            Value::Bytes(profile_digest.to_vec()),
            Value::Bytes(carrier_digest.to_vec()),
            Value::Text(carrier.relay_origin().into()),
            Value::Bytes(session_id.to_vec()),
            Value::Bytes(carrier_ceremony_id.to_vec()),
            Value::Bytes(carrier.claim_commitment().to_vec()),
            Value::Array(vec![
                Value::Text("allocator".into()),
                Value::Text("claimant".into()),
            ]),
        ]))?;
        let associated_data = [
            associated_data(
                Side::Allocator,
                carrier.expected_allocator_key(),
                profile_digest,
                carrier_digest,
            )?,
            associated_data(Side::Claimant, None, profile_digest, carrier_digest)?,
        ];
        let public_context = canonical(&Value::Array(vec![
            Value::Text("cbcl-pairing-public-context/credential-v2".into()),
            Value::Integer(2.into()),
            Value::Text(SUITE_ID.into()),
            Value::Text(PROFILE.into()),
            Value::Text(carrier.application_context().into()),
            Value::Bytes(profile_digest.to_vec()),
            Value::Bytes(carrier_digest.to_vec()),
            Value::Text(carrier.relay_origin().into()),
            Value::Bytes(session_id.to_vec()),
            Value::Bytes(carrier_ceremony_id.to_vec()),
            Value::Bytes(carrier.claim_commitment().to_vec()),
            carrier
                .expected_allocator_key()
                .map_or(Value::Null, |key| Value::Bytes(key.to_vec())),
            Value::Null,
        ]))?;
        Ok(Self {
            channel_identifier,
            public_context,
            session_id,
            carrier_ceremony_id,
            carrier_digest,
            associated_data,
        })
    }

    /// Begin role-bound CPace using only the separate `C` presence secret.
    pub fn start_cpace(
        &self,
        side: Side,
        presence: &CredentialV2Presence,
        fresh_scalar: [u8; 32],
    ) -> Result<(CpaceState, CpaceMessage), CredentialV2Error> {
        let peer = match side {
            Side::Allocator => Side::Claimant,
            Side::Claimant => Side::Allocator,
        };
        cpace::start_bound(
            side,
            presence.cpace_secret(),
            &self.channel_identifier,
            &self.session_id,
            self.associated_data(side),
            self.associated_data(peer),
            fresh_scalar,
        )
        .map_err(|_| CredentialV2Error::Cpace)
    }

    /// Borrow the exact CPace channel identifier.
    #[must_use]
    pub fn channel_identifier(&self) -> &[u8] {
        &self.channel_identifier
    }

    /// Borrow the exact thirteen-member secure-channel public context.
    #[must_use]
    pub fn public_context(&self) -> &[u8] {
        &self.public_context
    }

    /// Return the direct mailbox identifier used as CPace `sid`.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Return the sole carrier ceremony identifier.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.carrier_ceremony_id
    }

    /// Return the exact carrier digest.
    #[must_use]
    pub const fn carrier_digest(&self) -> &[u8; 32] {
        &self.carrier_digest
    }

    /// Borrow one role's exact CPace associated data.
    #[must_use]
    pub fn associated_data(&self, side: Side) -> &[u8] {
        &self.associated_data[match side {
            Side::Allocator => 0,
            Side::Claimant => 1,
        }]
    }
}

fn associated_data(
    side: Side,
    expected_key: Option<&[u8; 32]>,
    profile_digest: [u8; 32],
    carrier_digest: [u8; 32],
) -> Result<Vec<u8>, CredentialV2Error> {
    canonical(&Value::Array(vec![
        Value::Text("cbcl-pairing-ad/credential-v2".into()),
        Value::Text(
            match side {
                Side::Allocator => "allocator",
                Side::Claimant => "claimant",
            }
            .into(),
        ),
        expected_key.map_or(Value::Null, |key| Value::Bytes(key.to_vec())),
        Value::Bytes(profile_digest.to_vec()),
        Value::Bytes(carrier_digest.to_vec()),
    ]))
}

fn canonical(value: &Value) -> Result<Vec<u8>, CredentialV2Error> {
    cbor2::to_canonical_vec(value).map_err(|_| CredentialV2Error::Schema)
}
