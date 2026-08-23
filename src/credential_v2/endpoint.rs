use super::{
    decode_canonical, field, fixed_bytes, map_entries, recognise_credential_v2_intent,
    CredentialV2Display, CredentialV2Error, CredentialV2IntentAuthority,
    CredentialV2IntentVerifier, CredentialV2Kind, CredentialV2Object, CredentialV2OfferParser,
};
use crate::wire::Side;
use std::fmt;
use subtle::ConstantTimeEq;

/// Observable credential/v2 endpoint projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialV2Phase {
    /// No offer has been accepted.
    Begin,
    /// The authenticated offer is current.
    Offered,
    /// Preliminary approval is current.
    IntentApproved,
    /// Claimant preparation is current.
    Prepared,
    /// The allocator confirmed comparison or an existing binding.
    Confirmed,
    /// Final approval is current.
    FinalApproved,
    /// The payload is durably sent and only a receipt can advance.
    PayloadSent,
    /// Receipt, decline, or pre-payload refusal ended the protocol.
    Terminal,
}

/// One non-secret result of applying an endpoint object.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CredentialV2Advance {
    /// A new object advanced the phase without a display effect.
    Advanced,
    /// The claimant must display one authenticated private-field intent.
    DisplayIntent(Box<CredentialV2Display>),
    /// The exact latest object was seen again and caused no repeated effect.
    ExactRetransmission,
}

/// Immutable shared view passed to the consumer's exact successor parser.
#[derive(Debug)]
pub struct CredentialV2LogicalBody<'a> {
    kind: CredentialV2Kind,
    carrier_ceremony_id: [u8; 32],
    predecessor_digest: [u8; 32],
    bytes: &'a [u8],
}

impl CredentialV2LogicalBody<'_> {
    /// Return the closed envelope kind.
    #[must_use]
    pub const fn kind(&self) -> CredentialV2Kind {
        self.kind
    }

    /// Borrow the carrier ceremony identifier extracted by the shared parser.
    #[must_use]
    pub const fn carrier_ceremony_id(&self) -> &[u8; 32] {
        &self.carrier_ceremony_id
    }

    /// Borrow the exact prior-object digest extracted by the shared parser.
    #[must_use]
    pub const fn predecessor_digest(&self) -> &[u8; 32] {
        &self.predecessor_digest
    }

    /// Borrow the exact canonical unpadded logical-body bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// Consumer verifier for its nine closed credential/v2 successor grammars.
pub trait CredentialV2BodyVerifier: fmt::Debug + Send {
    /// Recognise the complete body and return only a closed verdict.
    fn verify(&mut self, body: &CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error>;
}

#[derive(Debug)]
struct LastObject {
    sender: Side,
    bytes: Vec<u8>,
    content_hash: [u8; 32],
}

/// Sender-, predecessor-, and intent-bound credential/v2 endpoint reducer.
#[derive(Debug)]
pub struct CredentialV2Endpoint {
    side: Side,
    carrier_ceremony_id: [u8; 32],
    phase: CredentialV2Phase,
    intent_digest: Option<[u8; 32]>,
    last: Option<LastObject>,
    body_verifier: Box<dyn CredentialV2BodyVerifier>,
}

impl CredentialV2Endpoint {
    /// Construct an effect-free endpoint at `begin`.
    #[must_use]
    pub fn new(
        side: Side,
        carrier_ceremony_id: [u8; 32],
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Self {
        Self {
            side,
            carrier_ceremony_id,
            phase: CredentialV2Phase::Begin,
            intent_digest: None,
            last: None,
            body_verifier,
        }
    }

    /// Return the current closed phase projection.
    #[must_use]
    pub const fn phase(&self) -> CredentialV2Phase {
        self.phase
    }

    /// Apply one locally generated object under this endpoint's sender role.
    pub fn send(
        &mut self,
        object: &CredentialV2Object,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        self.apply(object, self.side)
    }

    /// Apply one peer-generated successor object.
    pub fn receive(
        &mut self,
        object: &CredentialV2Object,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        self.apply(object, opposite(self.side))
    }

    /// Authenticate and apply the allocator's first Offer on a claimant.
    pub fn receive_offer(
        &mut self,
        object: &CredentialV2Object,
        authority: &CredentialV2IntentAuthority,
        parser: &mut dyn CredentialV2OfferParser,
        verifier: &mut dyn CredentialV2IntentVerifier,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        let sender = Side::Allocator;
        if let Some(result) = self.exact_retransmission(object, sender) {
            return result;
        }
        if self.side != Side::Claimant
            || self.phase != CredentialV2Phase::Begin
            || object.kind() != CredentialV2Kind::Offer
        {
            return self.fail(CredentialV2Error::Phase);
        }
        if authority.carrier_ceremony_id() != &self.carrier_ceremony_id {
            return self.fail(CredentialV2Error::Profile);
        }
        let display = match recognise_credential_v2_intent(object, authority, parser, verifier) {
            Ok(display) => display,
            Err(error) => return self.fail(error),
        };
        self.accept(object, sender, CredentialV2Phase::Offered);
        Ok(CredentialV2Advance::DisplayIntent(Box::new(display)))
    }

    fn apply(
        &mut self,
        object: &CredentialV2Object,
        sender: Side,
    ) -> Result<CredentialV2Advance, CredentialV2Error> {
        if let Some(result) = self.exact_retransmission(object, sender) {
            return result;
        }
        if self.phase == CredentialV2Phase::Terminal {
            return Err(CredentialV2Error::Terminal);
        }
        if self.phase == CredentialV2Phase::PayloadSent
            && object.kind() == CredentialV2Kind::Refusal
        {
            return Err(CredentialV2Error::Phase);
        }
        if !valid_sender(object.kind(), sender) {
            return self.fail(CredentialV2Error::Direction);
        }

        if object.kind() == CredentialV2Kind::Offer {
            if sender != Side::Allocator
                || self.side != Side::Allocator
                || self.phase != CredentialV2Phase::Begin
            {
                return self.fail(CredentialV2Error::Phase);
            }
            self.intent_digest = Some(*object.intent_digest());
            self.accept(object, sender, CredentialV2Phase::Offered);
            return Ok(CredentialV2Advance::Advanced);
        }

        let Some(expected_intent) = self.intent_digest else {
            return self.fail(CredentialV2Error::Phase);
        };
        if object.intent_digest() != &expected_intent {
            return self.fail(CredentialV2Error::Profile);
        }
        let next = match next_phase(self.phase, object.kind()) {
            Some(next) => next,
            None => return self.fail(CredentialV2Error::Phase),
        };
        let logical = match recognise_logical_body(object) {
            Ok(logical) => logical,
            Err(error) => return self.fail(error),
        };
        if logical.carrier_ceremony_id != self.carrier_ceremony_id {
            return self.fail(CredentialV2Error::Profile);
        }
        let Some(last) = &self.last else {
            return self.fail(CredentialV2Error::Phase);
        };
        if !bool::from(logical.predecessor_digest.ct_eq(&last.content_hash)) {
            return self.fail(CredentialV2Error::Predecessor);
        }
        if let Err(error) = self.body_verifier.verify(&logical) {
            return self.fail(error);
        }
        self.accept(object, sender, next);
        Ok(CredentialV2Advance::Advanced)
    }

    fn exact_retransmission(
        &mut self,
        object: &CredentialV2Object,
        sender: Side,
    ) -> Option<Result<CredentialV2Advance, CredentialV2Error>> {
        self.last.as_ref().and_then(|last| {
            if last.sender == sender && last.bytes == object.as_bytes() {
                Some(Ok(CredentialV2Advance::ExactRetransmission))
            } else {
                None
            }
        })
    }

    fn accept(&mut self, object: &CredentialV2Object, sender: Side, next: CredentialV2Phase) {
        if self.intent_digest.is_none() {
            self.intent_digest = Some(*object.intent_digest());
        }
        self.last = Some(LastObject {
            sender,
            bytes: object.as_bytes().to_vec(),
            content_hash: object.content_hash(),
        });
        self.phase = next;
    }

    fn fail<T>(&mut self, error: CredentialV2Error) -> Result<T, CredentialV2Error> {
        self.phase = CredentialV2Phase::Terminal;
        Err(error)
    }
}

fn recognise_logical_body(
    object: &CredentialV2Object,
) -> Result<CredentialV2LogicalBody<'_>, CredentialV2Error> {
    if object.kind() == CredentialV2Kind::Offer {
        return Err(CredentialV2Error::Schema);
    }
    let value = decode_canonical(object.body())?;
    let entries = map_entries(&value)?;
    let carrier_ceremony_id = fixed_bytes(field(
        entries,
        &ciborium::Value::Text("carrierCeremonyId".into()),
    )?)?;
    let predecessor_digest = fixed_bytes(field(
        entries,
        &ciborium::Value::Text("predecessorDigest".into()),
    )?)?;
    if object.kind() == CredentialV2Kind::Receipt {
        validate_receipt(entries)?;
    }
    Ok(CredentialV2LogicalBody {
        kind: object.kind(),
        carrier_ceremony_id,
        predecessor_digest,
        bytes: object.body(),
    })
}

fn validate_receipt(
    entries: &[(ciborium::Value, ciborium::Value)],
) -> Result<(), CredentialV2Error> {
    if entries.len() != 4 {
        return Err(CredentialV2Error::Schema);
    }
    let jws = field(entries, &ciborium::Value::Text("finalStatusJws".into()))?
        .as_text()
        .ok_or(CredentialV2Error::Schema)?;
    fixed_bytes::<32>(field(
        entries,
        &ciborium::Value::Text("finalStatusDigest".into()),
    )?)?;
    if !(1..=8_192).contains(&jws.len()) || !valid_compact_jws(jws) {
        return Err(CredentialV2Error::Schema);
    }
    Ok(())
}

fn valid_compact_jws(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

const fn valid_sender(kind: CredentialV2Kind, sender: Side) -> bool {
    match kind {
        CredentialV2Kind::Offer
        | CredentialV2Kind::ComparisonConfirmed
        | CredentialV2Kind::BindingConfirmed
        | CredentialV2Kind::Receipt => matches!(sender, Side::Allocator),
        CredentialV2Kind::IntentApprove
        | CredentialV2Kind::IntentDecline
        | CredentialV2Kind::Preparation
        | CredentialV2Kind::FinalApprove
        | CredentialV2Kind::FinalDecline
        | CredentialV2Kind::Payload => matches!(sender, Side::Claimant),
        CredentialV2Kind::Refusal => true,
    }
}

fn next_phase(phase: CredentialV2Phase, kind: CredentialV2Kind) -> Option<CredentialV2Phase> {
    if kind == CredentialV2Kind::Refusal && !matches!(phase, CredentialV2Phase::PayloadSent) {
        return Some(CredentialV2Phase::Terminal);
    }
    match (phase, kind) {
        (CredentialV2Phase::Offered, CredentialV2Kind::IntentApprove) => {
            Some(CredentialV2Phase::IntentApproved)
        }
        (CredentialV2Phase::Offered, CredentialV2Kind::IntentDecline)
        | (CredentialV2Phase::Confirmed, CredentialV2Kind::FinalDecline) => {
            Some(CredentialV2Phase::Terminal)
        }
        (CredentialV2Phase::IntentApproved, CredentialV2Kind::Preparation) => {
            Some(CredentialV2Phase::Prepared)
        }
        (
            CredentialV2Phase::Prepared,
            CredentialV2Kind::ComparisonConfirmed | CredentialV2Kind::BindingConfirmed,
        ) => Some(CredentialV2Phase::Confirmed),
        (CredentialV2Phase::Confirmed, CredentialV2Kind::FinalApprove) => {
            Some(CredentialV2Phase::FinalApproved)
        }
        (CredentialV2Phase::FinalApproved, CredentialV2Kind::Payload) => {
            Some(CredentialV2Phase::PayloadSent)
        }
        (CredentialV2Phase::PayloadSent, CredentialV2Kind::Receipt) => {
            Some(CredentialV2Phase::Terminal)
        }
        _ => None,
    }
}

const fn opposite(side: Side) -> Side {
    match side {
        Side::Allocator => Side::Claimant,
        Side::Claimant => Side::Allocator,
    }
}
