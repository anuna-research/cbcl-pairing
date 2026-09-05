//! SPEC-078 CON-001/002: independent manual bootstrap and three-word presence.
use super::handoff::{append_bstr, SchemaParser};
use super::{decode_carrier, encode_carrier, CredentialV2Carrier, CredentialV2PresenceCode};
use crate::wire::{claim_commitment, ClaimToken};
use base64ct::{Base64UrlUnpadded, Encoding};
use bip39::Language;
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PREFIX: &str = "SSPAIR-M1:";
const DOMAIN: &[u8] = b"selfsame-pairing-manual/v1";
const WORD_DOMAIN: &[u8] = b"selfsame-pairing-manual-words/v1\0";
const C_PREFIX: &[u8; 12] = b"SSPAIR-M1\0\0\0";
const MAX_CARRIER: usize = 2695;
const MAX_DECODED: usize = 2744;
const MAX_TEXT: usize = 3669;
const MAX_PHRASE: usize = 128;

/// Closed, redacted manual input failures; no variant retains input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialV2ManualError {
    /// Unsupported exact bootstrap prefix or domain.
    Version,
    /// A raw text or carrier byte bound was exceeded.
    Oversize,
    /// Noncanonical base64url or non-ASCII phrase.
    Encoding,
    /// Input is outside the complete bootstrap or three-word grammar.
    Schema,
    /// The public carrier failed its existing recognizer.
    Carrier,
    /// T does not open the carrier's commitment.
    Commitment,
    /// The supplied clock is at or beyond the relay expiry.
    Expired,
    /// Manual entry requires an allocator key in the carrier.
    AllocatorKeyRequired,
    /// The three checksum bits did not match.
    Checksum,
}

impl fmt::Display for CredentialV2ManualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CredentialV2ManualError {}

impl From<super::CredentialV2HandoffError> for CredentialV2ManualError {
    fn from(_: super::CredentialV2HandoffError) -> Self {
        Self::Schema
    }
}

/// Confidential carrier-plus-T bootstrap. It contains no phrase secret or verifier.
/// Only explicit encoding exposes T, inside zeroizing local transfer text.
pub struct CredentialV2ManualBootstrap {
    carrier: CredentialV2Carrier,
    claim_token: ClaimToken,
}

impl fmt::Debug for CredentialV2ManualBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialV2ManualBootstrap([REDACTED])")
    }
}

impl CredentialV2ManualBootstrap {
    /// Bind an independent shell-generated T to a live, keyed public carrier.
    pub fn new(
        carrier: CredentialV2Carrier,
        claim_token: [u8; 16],
        now: u64,
    ) -> Result<Self, CredentialV2ManualError> {
        let claim_token = ClaimToken::new(claim_token);
        if !bool::from(
            claim_commitment(*carrier.mailbox_id(), &claim_token).ct_eq(carrier.claim_commitment()),
        ) {
            return Err(CredentialV2ManualError::Commitment);
        }
        if carrier.expected_allocator_key().is_none() {
            return Err(CredentialV2ManualError::AllocatorKeyRequired);
        }
        if now >= carrier.relay_expires_at() {
            return Err(CredentialV2ManualError::Expired);
        }
        Ok(Self {
            carrier,
            claim_token,
        })
    }

    /// Borrow the unchanged public carrier; no T accessor is provided.
    #[must_use]
    pub const fn carrier(&self) -> &CredentialV2Carrier {
        &self.carrier
    }

    /// Recognize the complete bounded canonical bootstrap before returning authority.
    pub fn recognise(input: &str, now: u64) -> Result<Self, CredentialV2ManualError> {
        if input.len() > MAX_TEXT {
            return Err(CredentialV2ManualError::Oversize);
        }
        let suffix = input
            .strip_prefix(PREFIX)
            .ok_or(CredentialV2ManualError::Version)?;
        if suffix.is_empty() {
            return Err(CredentialV2ManualError::Encoding);
        }
        let mut storage = Zeroizing::new([0_u8; MAX_DECODED]);
        let decoded = Base64UrlUnpadded::decode(suffix, storage.as_mut())
            .map_err(|_| CredentialV2ManualError::Encoding)?;
        let mut parser = SchemaParser(decoded);
        if parser.byte()? != 0x83 {
            return Err(CredentialV2ManualError::Schema);
        }
        if parser.string(3)? != DOMAIN {
            return Err(CredentialV2ManualError::Version);
        }
        let public = parser.string(2)?;
        if public.is_empty() {
            return Err(CredentialV2ManualError::Schema);
        }
        if public.len() > MAX_CARRIER {
            return Err(CredentialV2ManualError::Oversize);
        }
        let t: &[u8; 16] = parser
            .string(2)?
            .try_into()
            .map_err(|_| CredentialV2ManualError::Schema)?;
        if !parser.0.is_empty() {
            return Err(CredentialV2ManualError::Schema);
        }
        let carrier = decode_carrier(public).map_err(|_| CredentialV2ManualError::Carrier)?;
        let bootstrap = Self::new(carrier, *t, now)?;
        if bootstrap.encode()?.as_bytes() != input.as_bytes() {
            return Err(CredentialV2ManualError::Schema);
        }
        Ok(bootstrap)
    }

    /// Bound both raw inputs, then completely recognize them locally.
    pub fn recognise_pair(
        bootstrap: &str,
        words: &str,
        now: u64,
    ) -> Result<(CredentialV2Carrier, CredentialV2PresenceCode), CredentialV2ManualError> {
        if bootstrap.len() > MAX_TEXT || words.len() > MAX_PHRASE {
            return Err(CredentialV2ManualError::Oversize);
        }
        let words = words.parse()?;
        Ok(Self::recognise(bootstrap, now)?.into_parts(words))
    }

    /// Encode only carrier and T for a private local transfer callback.
    pub fn encode(&self) -> Result<Zeroizing<String>, CredentialV2ManualError> {
        let public = encode_carrier(&self.carrier).map_err(|_| CredentialV2ManualError::Carrier)?;
        if public.len() > MAX_CARRIER {
            return Err(CredentialV2ManualError::Oversize);
        }
        let mut decoded = Zeroizing::new(Vec::with_capacity(MAX_DECODED));
        decoded.extend_from_slice(&[0x83, 0x78, 26]);
        decoded.extend_from_slice(DOMAIN);
        append_bstr(&mut decoded, &public);
        append_bstr(&mut decoded, self.claim_token.as_bytes());
        let mut suffix = Zeroizing::new([0_u8; MAX_TEXT - PREFIX.len()]);
        let encoded = Base64UrlUnpadded::encode(&decoded, suffix.as_mut())
            .map_err(|_| CredentialV2ManualError::Oversize)?;
        let mut text = Zeroizing::new(String::with_capacity(PREFIX.len() + encoded.len()));
        text.push_str(PREFIX);
        text.push_str(encoded);
        Ok(text)
    }

    /// Join the two completely recognized inputs in the existing typed presence value.
    #[must_use]
    pub fn into_parts(
        self,
        words: CredentialV2ManualWords,
    ) -> (CredentialV2Carrier, CredentialV2PresenceCode) {
        (
            self.carrier,
            CredentialV2PresenceCode::new(*words.cpace_secret(), *self.claim_token.as_bytes()),
        )
    }
}

/// Thirty secret bits represented by three full English list words and a checksum.
/// This uses BIP-39's pinned list only; it is not a BIP-39 mnemonic or seed.
pub struct CredentialV2ManualWords(Zeroizing<[u8; 16]>);

impl fmt::Debug for CredentialV2ManualWords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialV2ManualWords([REDACTED])")
    }
}

impl CredentialV2ManualWords {
    /// Map four fresh shell-supplied CSPRNG octets uniformly into 30 bits.
    #[must_use]
    pub fn from_csprng(random: [u8; 4]) -> Self {
        let n = Zeroizing::new(u32::from_be_bytes(random) & 0x3fff_ffff);
        let mut c = Zeroizing::new([0; 16]);
        c[..12].copy_from_slice(C_PREFIX);
        c[12..].copy_from_slice(&n.to_be_bytes());
        Self(c)
    }

    /// Supply mapped C to an explicitly Manual allocator; these bytes never select mode.
    #[must_use]
    pub fn cpace_secret(&self) -> &[u8; 16] {
        &self.0
    }

    pub(super) fn from_secret(c: [u8; 16]) -> Result<Self, CredentialV2ManualError> {
        let c = Zeroizing::new(c);
        if &c[..12] != C_PREFIX || c[12] & 0xc0 != 0 {
            return Err(CredentialV2ManualError::Schema);
        }
        Ok(Self(c))
    }

    /// Encode canonical lowercase words in zeroizing private transfer text.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<String> {
        let n = Zeroizing::new(u32::from_be_bytes(
            self.0[12..].try_into().expect("four bytes"),
        ));
        let bits = Zeroizing::new((u64::from(*n) << 3) | u64::from(checksum(*n)));
        let words = Language::English.word_list();
        let mut text = Zeroizing::new(String::with_capacity(26));
        for shift in [22, 11, 0] {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(words[(((*bits) >> shift) & 0x7ff) as usize]);
        }
        text
    }
}

impl FromStr for CredentialV2ManualWords {
    type Err = CredentialV2ManualError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > MAX_PHRASE {
            return Err(CredentialV2ManualError::Oversize);
        }
        if !input.is_ascii() {
            return Err(CredentialV2ManualError::Encoding);
        }
        let lower = Zeroizing::new(input.to_ascii_lowercase());
        let mut words = lower
            .split([' ', '\t', '\r', '\n'])
            .filter(|s| !s.is_empty());
        let mut bits = Zeroizing::new(0_u64);
        for _ in 0..3 {
            let word = words.next().ok_or(CredentialV2ManualError::Schema)?;
            let index = Language::English
                .word_list()
                .binary_search(&word)
                .map_err(|_| CredentialV2ManualError::Schema)?;
            *bits = (*bits << 11) | index as u64;
        }
        if words.next().is_some() {
            return Err(CredentialV2ManualError::Schema);
        }
        let n = Zeroizing::new((*bits >> 3) as u32);
        if !bool::from(checksum(*n).ct_eq(&((*bits & 7) as u8))) {
            return Err(CredentialV2ManualError::Checksum);
        }
        Ok(Self::from_csprng(n.to_be_bytes()))
    }
}

fn checksum(n: u32) -> u8 {
    let mut hash = Sha256::new();
    hash.update(WORD_DOMAIN);
    hash.update(n.to_be_bytes());
    let digest = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    digest[0] >> 5
}
