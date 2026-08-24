use super::{CredentialV2Carrier, CredentialV2Error, CredentialV2Presence};
use crate::wire::{claim_commitment, ClaimToken};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

const PREFIX: &str = "PAIR1";
const DOMAIN: &[u8] = b"selfsame credential/v2 presence code\0";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUPS: usize = 11;
const GROUP_OCTETS: usize = 5;
const DATA_BITS: usize = 272;
const ENCODED_BITS: usize = 275;

/// Separate, typed human-presence input for credential/v2.
///
/// The value carries independent raw CPace and mailbox-claim secrets. It is
/// never a machine-carrier member and exposes no secret accessor.
pub struct CredentialV2PresenceCode {
    cpace_secret: [u8; 16],
    claim_token: [u8; 16],
}

impl CredentialV2PresenceCode {
    /// Construct the canonical display code from independently generated secrets.
    #[must_use]
    pub const fn new(cpace_secret: [u8; 16], claim_token: [u8; 16]) -> Self {
        Self {
            cpace_secret,
            claim_token,
        }
    }

    /// Consume the typed code into the protocol's secret-bearing presence value.
    #[must_use]
    pub fn into_presence(self) -> CredentialV2Presence {
        CredentialV2Presence::new(self.cpace_secret, self.claim_token)
    }

    /// Require the separately entered claim token to open this exact carrier.
    pub fn bind_to_carrier(self, carrier: &CredentialV2Carrier) -> Result<Self, CredentialV2Error> {
        let commitment =
            claim_commitment(*carrier.mailbox_id(), &ClaimToken::new(self.claim_token));
        if commitment != *carrier.claim_commitment() {
            return Err(CredentialV2Error::Profile);
        }
        Ok(self)
    }

    fn payload(&self) -> [u8; 34] {
        let mut payload = [0_u8; 34];
        payload[..16].copy_from_slice(&self.cpace_secret);
        payload[16..32].copy_from_slice(&self.claim_token);
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.cpace_secret);
        digest.update(self.claim_token);
        payload[32..].copy_from_slice(&digest.finalize()[..2]);
        payload
    }
}

impl fmt::Display for CredentialV2PresenceCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let payload = self.payload();
        formatter.write_str(PREFIX)?;
        for group in 0..GROUPS {
            formatter.write_str("-")?;
            for offset in 0..GROUP_OCTETS {
                let symbol = group * GROUP_OCTETS + offset;
                let mut value = 0_u8;
                for bit in 0..5 {
                    let position = symbol * 5 + bit;
                    value <<= 1;
                    if position < DATA_BITS {
                        value |= (payload[position / 8] >> (7 - (position % 8))) & 1;
                    }
                }
                write!(formatter, "{}", char::from(ALPHABET[usize::from(value)]))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CredentialV2PresenceCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialV2PresenceCode([REDACTED])")
    }
}

impl FromStr for CredentialV2PresenceCode {
    type Err = CredentialV2Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !input.is_ascii() {
            return Err(CredentialV2Error::Schema);
        }
        let upper = input.to_ascii_uppercase();
        let mut groups = upper.split('-');
        if groups.next() != Some(PREFIX) {
            return Err(CredentialV2Error::Schema);
        }
        let groups: Vec<&str> = groups.collect();
        if groups.len() != GROUPS || groups.iter().any(|group| group.len() != GROUP_OCTETS) {
            return Err(CredentialV2Error::Schema);
        }
        let mut payload = [0_u8; 34];
        for (symbol, character) in groups.concat().bytes().enumerate() {
            let value = ALPHABET
                .iter()
                .position(|candidate| *candidate == character)
                .ok_or(CredentialV2Error::Schema)? as u8;
            for bit in 0..5 {
                let position = symbol * 5 + bit;
                let set = (value >> (4 - bit)) & 1;
                if position < DATA_BITS {
                    payload[position / 8] |= set << (7 - (position % 8));
                } else if position < ENCODED_BITS && set != 0 {
                    return Err(CredentialV2Error::Schema);
                }
            }
        }
        let mut cpace_secret = [0_u8; 16];
        cpace_secret.copy_from_slice(&payload[..16]);
        let mut claim_token = [0_u8; 16];
        claim_token.copy_from_slice(&payload[16..32]);
        let value = Self::new(cpace_secret, claim_token);
        if value.payload()[32..] != payload[32..] {
            return Err(CredentialV2Error::Profile);
        }
        Ok(value)
    }
}
