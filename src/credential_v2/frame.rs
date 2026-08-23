use super::{
    decode_canonical, field, fixed_bytes, map_entries, side, side_number, uint, CredentialV2Error,
};
use crate::{
    cpace::CpaceMessage,
    wire::{Direction, Side},
};
use ciborium::Value;

const MAX_CIPHERTEXT: usize = 69_572;

/// One closed credential/v2 CPace, Finished, or sealed frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialV2Frame {
    /// One version-2 CPace share and role-bound associated data.
    Cpace(CpaceMessage),
    /// One version-2 role-bound Finished value.
    Finished {
        /// Sender's fixed endpoint role.
        side: Side,
        /// HMAC-SHA-512 Finished value.
        value: [u8; 64],
    },
    /// One version-2 direction-bound AEAD envelope.
    Sealed {
        /// Fixed channel direction.
        direction: Direction,
        /// Contiguous direction-local counter.
        counter: u64,
        /// Ciphertext and authentication tag.
        ciphertext: Vec<u8>,
    },
}

impl CredentialV2Frame {
    /// Construct a v2 CPace frame from one role-bound message.
    pub fn cpace(message: &CpaceMessage) -> Result<Self, CredentialV2Error> {
        if message.associated_data.is_empty() || message.associated_data.len() > 256 {
            return Err(CredentialV2Error::Size);
        }
        Ok(Self::Cpace(message.clone()))
    }

    /// Borrow the authenticated CPace message when this is a CPace frame.
    #[must_use]
    pub const fn cpace_message(&self) -> Option<&CpaceMessage> {
        match self {
            Self::Cpace(message) => Some(message),
            _ => None,
        }
    }

    /// Return the sealed direction when this is an application frame.
    #[must_use]
    pub const fn direction(&self) -> Option<Direction> {
        match self {
            Self::Sealed { direction, .. } => Some(*direction),
            _ => None,
        }
    }

    pub(crate) const fn finished(&self) -> Option<(Side, &[u8; 64])> {
        match self {
            Self::Finished { side, value } => Some((*side, value)),
            _ => None,
        }
    }

    pub(crate) fn sealed(&self) -> Option<(Direction, u64, &[u8])> {
        match self {
            Self::Sealed {
                direction,
                counter,
                ciphertext,
            } => Some((*direction, *counter, ciphertext)),
            _ => None,
        }
    }
}

/// Encode one exact credential/v2 frame deterministically.
pub fn encode_frame(frame: &CredentialV2Frame) -> Result<Vec<u8>, CredentialV2Error> {
    let value = match frame {
        CredentialV2Frame::Cpace(message) => {
            if message.associated_data.is_empty() || message.associated_data.len() > 256 {
                return Err(CredentialV2Error::Size);
            }
            let nested = cbor2::to_canonical_vec(&Value::Array(vec![
                Value::Integer(2.into()),
                Value::Integer(side_number(message.side).into()),
                Value::Bytes(message.share.to_vec()),
                Value::Bytes(message.associated_data.clone()),
            ]))
            .map_err(|_| CredentialV2Error::Schema)?;
            Value::Map(vec![
                (Value::Text("v".into()), Value::Integer(2.into())),
                (Value::Text("kind".into()), Value::Text("cpace".into())),
                (
                    Value::Text("role".into()),
                    Value::Integer(side_number(message.side).into()),
                ),
                (Value::Text("message".into()), Value::Bytes(nested)),
            ])
        }
        CredentialV2Frame::Finished { side, value } => Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("kind".into()), Value::Text("finished".into())),
            (
                Value::Text("role".into()),
                Value::Integer(side_number(*side).into()),
            ),
            (Value::Text("value".into()), Value::Bytes(value.to_vec())),
        ]),
        CredentialV2Frame::Sealed {
            direction,
            counter,
            ciphertext,
        } => {
            if !(17..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
                return Err(CredentialV2Error::Size);
            }
            Value::Map(vec![
                (Value::Text("v".into()), Value::Integer(2.into())),
                (Value::Text("kind".into()), Value::Text("sealed".into())),
                (
                    Value::Text("direction".into()),
                    Value::Integer(direction_number(*direction).into()),
                ),
                (
                    Value::Text("counter".into()),
                    Value::Integer((*counter).into()),
                ),
                (
                    Value::Text("ciphertext".into()),
                    Value::Bytes(ciphertext.clone()),
                ),
            ])
        }
    };
    cbor2::to_canonical_vec(&value).map_err(|_| CredentialV2Error::Schema)
}

/// Recognise one complete deterministic credential/v2 frame.
pub fn decode_frame(input: &[u8]) -> Result<CredentialV2Frame, CredentialV2Error> {
    let value = decode_canonical(input)?;
    let entries = map_entries(&value)?;
    let version = uint(field(entries, &Value::Text("v".into()))?)?;
    let kind = field(entries, &Value::Text("kind".into()))?
        .as_text()
        .ok_or(CredentialV2Error::Schema)?;
    if version != 2 {
        return Err(CredentialV2Error::Schema);
    }
    let frame = match kind {
        "cpace" if entries.len() == 4 => {
            let outer_side = side(field(entries, &Value::Text("role".into()))?)?;
            let nested_bytes = field(entries, &Value::Text("message".into()))?
                .as_bytes()
                .ok_or(CredentialV2Error::Schema)?;
            let nested = decode_canonical(nested_bytes)?;
            let Value::Array(parts) = nested else {
                return Err(CredentialV2Error::Schema);
            };
            let [version, role, share, associated_data] = parts.as_slice() else {
                return Err(CredentialV2Error::Schema);
            };
            let nested_side = side(role)?;
            let associated_data = associated_data
                .as_bytes()
                .ok_or(CredentialV2Error::Schema)?;
            if uint(version)? != 2
                || nested_side != outer_side
                || associated_data.is_empty()
                || associated_data.len() > 256
            {
                return Err(CredentialV2Error::Schema);
            }
            CredentialV2Frame::Cpace(CpaceMessage {
                side: outer_side,
                share: fixed_bytes(share)?,
                associated_data: associated_data.to_vec(),
            })
        }
        "finished" if entries.len() == 4 => CredentialV2Frame::Finished {
            side: side(field(entries, &Value::Text("role".into()))?)?,
            value: fixed_bytes(field(entries, &Value::Text("value".into()))?)?,
        },
        "sealed" if entries.len() == 5 => {
            let ciphertext = field(entries, &Value::Text("ciphertext".into()))?
                .as_bytes()
                .ok_or(CredentialV2Error::Schema)?;
            if !(17..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
                return Err(CredentialV2Error::Size);
            }
            CredentialV2Frame::Sealed {
                direction: direction(field(entries, &Value::Text("direction".into()))?)?,
                counter: uint(field(entries, &Value::Text("counter".into()))?)?,
                ciphertext: ciphertext.to_vec(),
            }
        }
        _ => return Err(CredentialV2Error::Schema),
    };
    if encode_frame(&frame)? != input {
        return Err(CredentialV2Error::NonDeterministic);
    }
    Ok(frame)
}

fn direction(value: &Value) -> Result<Direction, CredentialV2Error> {
    match uint(value)? {
        0 => Ok(Direction::AllocatorToClaimant),
        1 => Ok(Direction::ClaimantToAllocator),
        _ => Err(CredentialV2Error::Schema),
    }
}

const fn direction_number(direction: Direction) -> u64 {
    match direction {
        Direction::AllocatorToClaimant => 0,
        Direction::ClaimantToAllocator => 1,
    }
}
