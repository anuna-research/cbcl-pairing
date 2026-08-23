//! Standalone credential/v2 carrier, channel, and endpoint primitives.
//!
//! These types are disjoint from credential/v1. Generic bytes or a caller
//! version cannot select this protocol.

mod carrier;
mod channel;
mod context;
mod frame;
mod object;

pub use carrier::{
    decode_carrier, encode_carrier, CredentialV2Carrier, CredentialV2CarrierInput,
    CredentialV2Presence,
};
pub use channel::{PendingCredentialV2Channel, SecureCredentialV2Channel};
pub use context::CredentialV2Context;
pub use frame::{decode_frame, encode_frame, CredentialV2Frame};
pub use object::{
    decode_object, CredentialV2Kind, CredentialV2Object, CONTROL_PADDING_BYTES, LARGE_PADDING_BYTES,
};

use ciborium::Value;
use std::{collections::BTreeSet, fmt, io::Cursor};

/// Credential/v2 recognition, cryptographic, or state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2Error {
    /// Input is not one complete well-formed CBOR value.
    MalformedCbor,
    /// Extra bytes follow one CBOR value.
    TrailingBytes,
    /// Input is not the required deterministic encoding.
    NonDeterministic,
    /// A map contains a duplicate key.
    DuplicateKey,
    /// A closed grammar or typed bound failed.
    Schema,
    /// A carrier application or relay origin is invalid.
    Origin,
    /// CPace input or peer authentication failed.
    Cpace,
    /// The fixed key schedule failed.
    KeySchedule,
    /// A Finished value did not verify.
    Finished,
    /// A frame used the wrong role or direction.
    Direction,
    /// A frame counter was not exact or was exhausted.
    Counter,
    /// Authenticated decryption failed.
    Authentication,
    /// A message fell outside its exact size bound.
    Size,
    /// A prior failure made the channel terminal.
    Terminal,
}

impl fmt::Display for CredentialV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CredentialV2Error {}

fn decode_canonical(input: &[u8]) -> Result<Value, CredentialV2Error> {
    let mut cursor = Cursor::new(input);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| CredentialV2Error::MalformedCbor)?;
    if usize::try_from(cursor.position()).map_err(|_| CredentialV2Error::TrailingBytes)?
        != input.len()
    {
        return Err(CredentialV2Error::TrailingBytes);
    }
    if contains_duplicate_map_key(&value)? {
        return Err(CredentialV2Error::DuplicateKey);
    }
    let canonical =
        cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::NonDeterministic)?;
    if canonical != input {
        return Err(CredentialV2Error::NonDeterministic);
    }
    Ok(value)
}

fn contains_duplicate_map_key(value: &Value) -> Result<bool, CredentialV2Error> {
    match value {
        Value::Map(entries) => {
            let mut keys = BTreeSet::new();
            for (key, child) in entries {
                let encoded = cbor2::to_canonical_vec(key)
                    .map_err(|_| CredentialV2Error::NonDeterministic)?;
                if !keys.insert(encoded)
                    || contains_duplicate_map_key(key)?
                    || contains_duplicate_map_key(child)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Array(values) => {
            for value in values {
                if contains_duplicate_map_key(value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Tag(_, value) => contains_duplicate_map_key(value),
        _ => Ok(false),
    }
}

fn map_entries(value: &Value) -> Result<&[(Value, Value)], CredentialV2Error> {
    value
        .as_map()
        .map(Vec::as_slice)
        .ok_or(CredentialV2Error::Schema)
}

fn text_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str, CredentialV2Error> {
    field(entries, &Value::Text(key.into()))?
        .as_text()
        .ok_or(CredentialV2Error::Schema)
}

fn bytes_field<const LENGTH: usize>(
    entries: &[(Value, Value)],
    key: &str,
) -> Result<[u8; LENGTH], CredentialV2Error> {
    fixed_bytes(field(entries, &Value::Text(key.into()))?)
}

fn uint_field(entries: &[(Value, Value)], key: &str) -> Result<u64, CredentialV2Error> {
    uint(field(entries, &Value::Text(key.into()))?)
}

fn field<'a>(entries: &'a [(Value, Value)], key: &Value) -> Result<&'a Value, CredentialV2Error> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value))
        .ok_or(CredentialV2Error::Schema)
}

fn optional_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    let key = Value::Text(key.into());
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate == &key).then_some(value))
}

fn fixed_bytes<const LENGTH: usize>(value: &Value) -> Result<[u8; LENGTH], CredentialV2Error> {
    value
        .as_bytes()
        .ok_or(CredentialV2Error::Schema)?
        .as_slice()
        .try_into()
        .map_err(|_| CredentialV2Error::Schema)
}

fn uint(value: &Value) -> Result<u64, CredentialV2Error> {
    let Value::Integer(integer) = value else {
        return Err(CredentialV2Error::Schema);
    };
    u64::try_from(*integer).map_err(|_| CredentialV2Error::Schema)
}

fn side_number(side: crate::wire::Side) -> u64 {
    match side {
        crate::wire::Side::Allocator => 0,
        crate::wire::Side::Claimant => 1,
    }
}

fn side(value: &Value) -> Result<crate::wire::Side, CredentialV2Error> {
    match uint(value)? {
        0 => Ok(crate::wire::Side::Allocator),
        1 => Ok(crate::wire::Side::Claimant),
        _ => Err(CredentialV2Error::Schema),
    }
}
