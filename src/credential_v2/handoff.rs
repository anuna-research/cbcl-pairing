//! Confidential local handoff: SPEC-001 REQ-031 / SPEC-077 CON-001.
use super::{decode_carrier, encode_carrier, CredentialV2Carrier, CredentialV2PresenceCode};
use crate::wire::{claim_commitment, ClaimToken};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PREFIX: &str = "SSPAIR1:";
const DOMAIN: &[u8] = b"selfsame-pairing-handoff/v1";
const MAX_CARRIER: usize = 2695;
const MAX_DECODED: usize = 2762;
const MAX_TEXT: usize = 3691;

/// Closed handoff recognition errors. No variant retains input or secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2HandoffError {
    /// The exact prefix or handoff version is unsupported.
    Version,
    /// The handoff or carrier exceeds its fixed byte bound.
    Oversize,
    /// The suffix is not canonical unpadded base64url.
    Encoding,
    /// The outer value is not the complete deterministic fixed CBOR schema.
    Schema,
    /// The public carrier failed its existing credential/v2 recognizer.
    Carrier,
    /// The claim token does not match the carrier's existing commitment.
    Commitment,
}

impl fmt::Display for CredentialV2HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CredentialV2HandoffError {}

/// Confidential bootstrap material containing a public carrier and independent C/T.
///
/// Secret storage is erased on drop through the owned presence code. Explicit
/// encoding returns zeroizing text; this type deliberately has no `Display`.
/// Disclosure permits a pairing attempt, without granting identity authority.
pub struct CredentialV2Handoff {
    carrier: CredentialV2Carrier,
    presence: CredentialV2PresenceCode,
}

impl CredentialV2Handoff {
    /// Bind the presence to exactly `claim_commitment(M, T)` in this carrier.
    /// C remains independent and is never part of the claim commitment.
    pub fn new(
        carrier: CredentialV2Carrier,
        presence: CredentialV2PresenceCode,
    ) -> Result<Self, CredentialV2HandoffError> {
        let (_, t) = presence.secrets();
        let commitment = claim_commitment(*carrier.mailbox_id(), &ClaimToken::new(*t));
        if !bool::from(commitment.ct_eq(carrier.claim_commitment())) {
            return Err(CredentialV2HandoffError::Commitment);
        }
        Ok(Self { carrier, presence })
    }

    /// Borrow only the original public carrier, whose bytes and digest are unchanged.
    #[must_use]
    pub fn carrier(&self) -> &CredentialV2Carrier {
        &self.carrier
    }

    /// Encode canonical confidential text for explicit local QR or copy transfer.
    /// Every owned secret-bearing encoding buffer is zeroized on drop.
    pub fn encode(&self) -> Result<Zeroizing<String>, CredentialV2HandoffError> {
        let public =
            encode_carrier(&self.carrier).map_err(|_| CredentialV2HandoffError::Carrier)?;
        if public.len() > MAX_CARRIER {
            return Err(CredentialV2HandoffError::Oversize);
        }
        // Reserving the proven maximum prevents reallocations of secret bytes.
        let mut decoded = Zeroizing::new(Vec::with_capacity(MAX_DECODED));
        decoded.extend_from_slice(&[0x84, 0x78, 27]);
        decoded.extend_from_slice(DOMAIN);
        append_bstr(&mut decoded, &public);
        let (c, t) = self.presence.secrets();
        append_bstr(&mut decoded, c);
        append_bstr(&mut decoded, t);
        let mut suffix = Zeroizing::new([0_u8; MAX_TEXT - PREFIX.len()]);
        let encoded = Base64UrlUnpadded::encode(&decoded, suffix.as_mut())
            .map_err(|_| CredentialV2HandoffError::Oversize)?;
        let mut text = Zeroizing::new(String::with_capacity(PREFIX.len() + encoded.len()));
        text.push_str(PREFIX);
        text.push_str(encoded);
        Ok(text)
    }

    /// Transfer the exact public carrier and owned, typed secret presence input.
    #[must_use]
    pub fn into_parts(self) -> (CredentialV2Carrier, CredentialV2PresenceCode) {
        (self.carrier, self.presence)
    }
}

impl fmt::Debug for CredentialV2Handoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialV2Handoff([REDACTED])")
    }
}

impl FromStr for CredentialV2Handoff {
    type Err = CredentialV2HandoffError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // First operation: refuse lexical oversize before any allocation or scan.
        if input.len() > MAX_TEXT {
            return Err(CredentialV2HandoffError::Oversize);
        }
        let suffix = input
            .strip_prefix(PREFIX)
            .ok_or(CredentialV2HandoffError::Version)?;
        if suffix.is_empty() {
            return Err(CredentialV2HandoffError::Encoding);
        }
        let mut storage = Zeroizing::new([0_u8; MAX_DECODED]);
        let decoded = Base64UrlUnpadded::decode(suffix, storage.as_mut())
            .map_err(|_| CredentialV2HandoffError::Encoding)?;
        let mut parser = SchemaParser(decoded);
        if parser.byte()? != 0x84 {
            return Err(CredentialV2HandoffError::Schema);
        }
        if parser.string(3)? != DOMAIN {
            return Err(CredentialV2HandoffError::Version);
        }
        let public = parser.string(2)?;
        if public.is_empty() {
            return Err(CredentialV2HandoffError::Schema);
        }
        if public.len() > MAX_CARRIER {
            return Err(CredentialV2HandoffError::Oversize);
        }
        let c: &[u8; 16] = parser
            .string(2)?
            .try_into()
            .map_err(|_| CredentialV2HandoffError::Schema)?;
        let t: &[u8; 16] = parser
            .string(2)?
            .try_into()
            .map_err(|_| CredentialV2HandoffError::Schema)?;
        if !parser.0.is_empty() {
            return Err(CredentialV2HandoffError::Schema);
        }
        // Full outer recognition precedes the existing public-carrier recognizer.
        let carrier = decode_carrier(public).map_err(|_| CredentialV2HandoffError::Carrier)?;
        let handoff = Self::new(carrier, CredentialV2PresenceCode::new(*c, *t))?;
        if handoff.encode()?.as_bytes() != input.as_bytes() {
            return Err(CredentialV2HandoffError::Schema);
        }
        Ok(handoff)
    }
}

// All callers supply at most MAX_CARRIER (< u16::MAX) bytes.
pub(super) fn append_bstr(output: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        0..=23 => output.push(0x40 | bytes.len() as u8),
        24..=255 => output.extend_from_slice(&[0x58, bytes.len() as u8]),
        _ => {
            output.push(0x59);
            output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
}

// A nonrecursive recognizer for just the fixed array's string members. It
// borrows slices, never allocates, and rejects nonminimal / indefinite lengths,
// tags, containers and all length encodings exceeding this bounded language.
pub(super) struct SchemaParser<'a>(pub(super) &'a [u8]);

impl<'a> SchemaParser<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CredentialV2HandoffError> {
        let value = self
            .0
            .get(..length)
            .ok_or(CredentialV2HandoffError::Schema)?;
        self.0 = &self.0[length..];
        Ok(value)
    }

    pub(super) fn byte(&mut self) -> Result<u8, CredentialV2HandoffError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn string(&mut self, major: u8) -> Result<&'a [u8], CredentialV2HandoffError> {
        let head = self.byte()?;
        if head >> 5 != major {
            return Err(CredentialV2HandoffError::Schema);
        }
        let length = match head & 31 {
            n @ 0..=23 => usize::from(n),
            24 => {
                let n = self.byte()?;
                if n < 24 {
                    return Err(CredentialV2HandoffError::Schema);
                }
                usize::from(n)
            }
            25 => {
                let n = u16::from_be_bytes([self.byte()?, self.byte()?]);
                if n <= 255 {
                    return Err(CredentialV2HandoffError::Schema);
                }
                usize::from(n)
            }
            _ => return Err(CredentialV2HandoffError::Schema),
        };
        self.take(length)
    }
}
