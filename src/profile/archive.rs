//! SPEC-054 CON-012: bounded enrollment descriptor, not archive key custody.
use super::*;

/// Archive application identifier.
pub const APPLICATION: &str = "anuna.io/archive/v1";
/// Exact archive enrollment action.
pub const ACTION: &str = "enroll-archive";
/// Exact enrollment descriptor payload identifier.
pub const PAYLOAD: &str = "anuna.io/archive-enrollment/v1";
/// Fixed authority summary; peers cannot substitute misleading prose.
pub const SUMMARY: &str = "Add this device to the personal archive.";

/// Complete public authority and recipient binding approved in one intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claims {
    /// Canonical archive owner, subsequently checked by the archive verifier.
    pub owner: String,
    /// Archive chain identifier.
    pub chain: [u8; 32],
    /// Exact admitted predecessor manifest digest.
    pub previous: [u8; 32],
    /// Enrolled author signing key, not the pairing ceremony-key digest.
    pub allocator: [u8; 32],
    /// New archive device signing key.
    pub recipient: [u8; 32],
    /// New independent archive HPKE public key.
    pub hpke: [u8; 32],
}

impl Claims {
    /// Encode the two exact canonical claim maps.
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
        bounded_text(&self.owner, 256).map_err(|_| ProfileError::InvalidClaim)?;
        if self.allocator == self.recipient {
            return Err(ProfileError::InvalidClaim);
        }
        Ok((
            encode_map(vec![
                ("owner", Value::Text(self.owner.clone())),
                ("chain", Value::Bytes(self.chain.to_vec())),
                ("previous", Value::Bytes(self.previous.to_vec())),
                ("allocator", Value::Bytes(self.allocator.to_vec())),
            ])?,
            encode_map(vec![
                ("recipient", Value::Bytes(self.recipient.to_vec())),
                ("hpke", Value::Bytes(self.hpke.to_vec())),
            ])?,
        ))
    }
    /// Recognize both bounded claim maps completely before use.
    pub fn decode(allocator: &[u8], claimant: &[u8]) -> Result<Self, ProfileError> {
        let e = ProfileError::InvalidClaim;
        bounded_bytes(allocator, 1, 1024).map_err(|_| e)?;
        bounded_bytes(claimant, 1, 256).map_err(|_| e)?;
        let a = canonical_map(allocator, 4, e)?;
        let c = canonical_map(claimant, 2, e)?;
        let result = Self {
            owner: text_field(&a, "owner", 256, e)?,
            chain: fixed(&a, "chain", e)?,
            previous: fixed(&a, "previous", e)?,
            allocator: fixed(&a, "allocator", e)?,
            recipient: fixed(&c, "recipient", e)?,
            hpke: fixed(&c, "hpke", e)?,
        };
        result.encode()?;
        Ok(result)
    }
    fn binding(&self) -> Result<[u8; 32], ProfileError> {
        let (a, c) = self.encode()?;
        let value = Value::Array(vec![
            Value::Text(APPLICATION.into()),
            Value::Text(ACTION.into()),
            Value::Bytes(a),
            Value::Bytes(c),
        ]);
        Ok(
            Sha256::digest(
                cbor2::to_canonical_vec(&value).map_err(|_| ProfileError::InvalidClaim)?,
            )
            .into(),
        )
    }
}

/// Public signed enrollment proposal; key pages remain separate encrypted data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enrollment {
    /// Exact claims repeated from the approved intent.
    pub claims: Claims,
    /// Signed archive manifest requiring archive-core recognition and admission.
    pub manifest: Vec<u8>,
}
impl Enrollment {
    /// Encode a bounded descriptor without including archive secrets.
    pub fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        bounded_bytes(&self.manifest, 1, 16384).map_err(|_| ProfileError::InvalidPayload)?;
        let (a, c) = self.claims.encode()?;
        encode_map(vec![
            ("allocator-claim", Value::Bytes(a)),
            ("claimant-claim", Value::Bytes(c)),
            ("manifest", Value::Bytes(self.manifest.clone())),
        ])
    }
    /// Fully recognize syntax; this does not verify manifest authority.
    pub fn decode(input: &[u8]) -> Result<Self, ProfileError> {
        let e = ProfileError::InvalidPayload;
        bounded_bytes(input, 1, 18000).map_err(|_| e)?;
        let fields = canonical_map(input, 3, e)?;
        let a = bytes_field(&fields, "allocator-claim", 1024, e)?;
        let c = bytes_field(&fields, "claimant-claim", 256, e)?;
        Ok(Self {
            claims: Claims::decode(&a, &c).map_err(|_| e)?,
            manifest: bytes_field(&fields, "manifest", 16384, e)?,
        })
    }
}

/// Archive-owned semantic verifier, invoked only after pairing approval/binding.
pub trait EnrollmentVerifier: fmt::Debug + Send {
    /// Verify the manifest signature and exact enrollment against authenticated
    /// predecessor history. Hub admission and full custody are still required.
    fn verify(&mut self, enrollment: &Enrollment) -> Result<(), ProfileError>;
}

/// Endpoint-local archive profile. It never releases archive key material.
#[derive(Debug)]
pub struct ArchiveProfile {
    descriptor: ProfileDescriptor,
    expected_ceremony: [[u8; 32]; 2],
    expected_signing: [[u8; 32]; 2],
    verifier: Box<dyn EnrollmentVerifier>,
}
impl ArchiveProfile {
    /// Construct with locally expected ceremony digests and archive signing
    /// keys, each ordered allocator then claimant. These are distinct domains.
    #[must_use]
    pub fn new(
        expected_ceremony: [[u8; 32]; 2],
        expected_signing: [[u8; 32]; 2],
        verifier: Box<dyn EnrollmentVerifier>,
    ) -> Self {
        Self {
            descriptor: ProfileDescriptor {
                application: APPLICATION,
                payload_type: PAYLOAD,
                carrier: CarrierContract {
                    carrier: "128-bit direct invitation",
                    locator: LocatorKind::Direct,
                    minimum_entropy_bits: 128,
                },
                approval_authority: "explicit archive enrollment approval",
                grant_verifier: "archive predecessor and enrollment verifier",
            },
            expected_ceremony,
            expected_signing,
            verifier,
        }
    }
}
impl ApplicationProfile for ArchiveProfile {
    fn descriptor(&self) -> &ProfileDescriptor {
        &self.descriptor
    }
    fn recognise_invitation(&self, invitation: &Invitation) -> Result<(), ProfileError> {
        common_invitation(&self.descriptor, invitation)?;
        if invitation.secret.len() != 16
            || invitation.expected_allocator_key != Some(self.expected_ceremony[0])
            || invitation.expected_claimant_key != Some(self.expected_ceremony[1])
        {
            return Err(ProfileError::InvalidInvitation);
        }
        Ok(())
    }
    fn recognise_intent(&mut self, intent: &PairingIntent) -> Result<ProfileIntent, ProfileError> {
        common_intent(&self.descriptor, ACTION, intent)?;
        if intent.authority_summary != SUMMARY {
            return Err(ProfileError::InvalidClaim);
        }
        let claims = Claims::decode(&intent.allocator_claim, &intent.claimant_claim)?;
        if [claims.allocator, claims.recipient] != self.expected_signing {
            return Err(ProfileError::InvalidClaim);
        }
        Ok(ProfileIntent::new(
            display_intent(
                intent,
                vec![
                    display("archive owner", claims.owner.clone()),
                    display("archive recipient", hex_key(&claims.recipient)),
                    display("archive chain", hex_key(&claims.chain)),
                ],
            ),
            claims.binding()?,
        ))
    }
    fn recognise_payload(
        &self,
        binding: &ProfileBinding,
        payload: &ApplicationPayload,
    ) -> Result<RecognisedPayload, ProfileError> {
        payload_type(&self.descriptor, payload)?;
        let enrollment = Enrollment::decode(&payload.body)?;
        if enrollment.claims.binding()? != binding.0 {
            return Err(ProfileError::InvalidPayload);
        }
        Ok(recognised(&self.descriptor, payload))
    }
    fn authorize_payload(
        &mut self,
        payload: RecognisedPayload,
    ) -> Result<AuthorisedGrant, ProfileError> {
        if payload.application != APPLICATION || payload.payload_type != PAYLOAD {
            return Err(ProfileError::InvalidPayloadType);
        }
        self.verifier.verify(&Enrollment::decode(&payload.body)?)?;
        Ok(payload.grant())
    }
}
fn fixed(fields: &[(Value, Value)], name: &str, e: ProfileError) -> Result<[u8; 32], ProfileError> {
    bytes_field(fields, name, 32, e)?.try_into().map_err(|_| e)
}
fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}
