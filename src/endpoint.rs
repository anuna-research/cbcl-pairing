//! Security-state reducer composed around the CBCL protocol monitors.
//!
//! CBCL owns legal predecessors and role directions. This reducer owns only
//! invitation consumption, cryptographic activation/erasure, decision
//! uniqueness, and application-effect release. Its small amount of explicit
//! state is therefore security state, not a duplicate choreography graph.

use crate::{
    cbcl_protocol::{
        build_bootstrap_control, build_session_control, build_session_opener, ceremony_id,
        BootstrapMonitor, BootstrapPerformative, CeremonyKeyId, CeremonySigningKey, PairingRole,
        ProtocolVerdict, SessionMonitor, SessionPerformative,
    },
    channel::{PendingChannel, SecureChannel},
    profile::{ApplicationProfile, AuthorisedGrant, DisplayIntent, ProfileBinding},
    wire::{
        decode_application_payload, decode_invitation, decode_pairing_decision,
        decode_pairing_intent, decode_sealed_plaintext, encode_application_payload,
        encode_channel_frame, encode_pairing_decision, encode_pairing_intent,
        encode_sealed_plaintext, ApplicationPayload, ChannelFrame, Decision, PairingDecision,
        PairingIntent, SealedPlaintext, Side,
    },
};
use cbcl_core::message::CausedBy;
use ciborium::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAX_PENDING_CONTROLS: usize = 16;

/// Durable local status of one exact invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationStatus {
    /// No online peer frame has been bound to the invitation.
    Unused,
    /// One exact mailbox, peer frame, and transcript are bound for crash resume.
    Bound,
    /// The invitation can never start or resume another attempt.
    Spent,
}

/// Result of atomically binding the first online attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindOutcome {
    /// The unused record was bound for the first time.
    Bound,
    /// The exact active binding was presented again for resume.
    Resumed,
}

/// Persistable, secret-free invitation-consumption record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationRecord {
    invitation_digest: [u8; 32],
    status: InvitationStatus,
    binding: Option<[u8; 32]>,
}

impl InvitationRecord {
    /// Create an unused record for exact invitation bytes.
    #[must_use]
    pub fn new(invitation: &[u8]) -> Self {
        Self {
            invitation_digest: Sha256::digest(invitation).into(),
            status: InvitationStatus::Unused,
            binding: None,
        }
    }

    /// Atomically bind the invitation before processing a peer CPace frame.
    pub fn bind(
        &mut self,
        mailbox_id: [u8; 32],
        peer_cpace_frame: &[u8],
        public_context: &[u8],
    ) -> Result<BindOutcome, ReducerError> {
        let binding = attempt_binding(
            &self.invitation_digest,
            &mailbox_id,
            peer_cpace_frame,
            public_context,
        )?;
        match self.status {
            InvitationStatus::Unused => {
                self.status = InvitationStatus::Bound;
                self.binding = Some(binding);
                Ok(BindOutcome::Bound)
            }
            InvitationStatus::Bound if self.binding == Some(binding) => Ok(BindOutcome::Resumed),
            InvitationStatus::Bound => {
                self.spend();
                Err(ReducerError::Invitation)
            }
            InvitationStatus::Spent => Err(ReducerError::Invitation),
        }
    }

    /// Return the durable status.
    #[must_use]
    pub fn status(&self) -> InvitationStatus {
        self.status
    }

    fn spend(&mut self) {
        self.status = InvitationStatus::Spent;
        self.binding = None;
    }
}

/// Observable effect emitted only after all preceding gates pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointEffect {
    /// Transmit one already protected pairing-channel frame.
    SendFrame(ChannelFrame),
    /// Display a channel-authenticated and fully profile-recognised intent.
    DisplayIntent(DisplayIntent),
    /// Deliver one approved, digest-bound, profile-authorised grant.
    DeliverGrant(AuthorisedGrant),
    /// Close the blind mailbox after terminal completion or failure.
    CloseMailbox,
}

/// Stable terminal classification for interoperation vectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReason {
    /// Explicit user decline.
    Declined,
    /// A CBCL control or role verdict was a permanent violation.
    ProtocolViolation,
    /// CPace key confirmation failed.
    KeyConfirmation,
    /// AEAD direction, counter, tag, or frame recognition failed.
    Channel,
    /// An intent or payload digest did not match the accepted intent.
    IntentMismatch,
    /// An application profile rejected an invitation, claim, or grant.
    Profile,
    /// Approval and decline both appeared for one intent.
    DecisionConflict,
    /// A different attempt was presented for an already bound invitation.
    InvitationMismatch,
    /// A recognised outer frame carried malformed inner data.
    Malformed,
}

/// Endpoint reducer failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReducerError {
    /// The invitation record cannot be used for this attempt.
    Invitation,
    /// A frame arrived from the wrong fixed side.
    WrongSide,
    /// CBCL recognition or verification failed.
    Protocol,
    /// Channel confirmation or AEAD processing failed.
    Channel,
    /// Deterministic CBOR recognition failed.
    Recognition,
    /// The requested local operation is unavailable at this security phase.
    Phase,
    /// A decision or payload names a different intent.
    IntentDigest,
    /// The endpoint-local application profile rejected input.
    Profile,
    /// Both decision siblings were observed.
    DecisionConflict,
    /// The reducer is already terminal.
    Terminal,
}

impl fmt::Display for ReducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ReducerError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntentRecord {
    digest: [u8; 32],
    control_hash: String,
    profile_binding: ProfileBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DecisionRecord {
    decision: Decision,
    control_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedApplication {
    Intent(PairingIntent),
    Decision(PairingDecision),
    Payload(ApplicationPayload),
}

impl DecodedApplication {
    fn performative(&self) -> SessionPerformative {
        match self {
            Self::Intent(_) => SessionPerformative::Intent,
            Self::Decision(value) => match value.decision {
                Decision::Approve => SessionPerformative::Approve,
                Decision::Decline => SessionPerformative::Decline,
            },
            Self::Payload(_) => SessionPerformative::Payload,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingApplication {
    plaintext: SealedPlaintext,
    decoded: DecodedApplication,
}

/// Reducer for one endpoint after local CPace computation has begun.
pub struct EndpointReducer {
    side: Side,
    application: String,
    ceremony: String,
    expected_role_keys: [Option<[u8; 32]>; 2],
    profile: Box<dyn ApplicationProfile>,
    record: InvitationRecord,
    ceremony_key: Option<CeremonySigningKey>,
    bootstrap: Option<BootstrapMonitor>,
    pending_channel: Option<PendingChannel>,
    channel: Option<SecureChannel>,
    session: Option<SessionMonitor>,
    allocator_cpace_hash: String,
    claimant_cpace_hash: String,
    local_finished: Option<ChannelFrame>,
    pending_finished: Option<ChannelFrame>,
    pending_applications: Vec<PendingApplication>,
    intent: Option<IntentRecord>,
    decision: Option<DecisionRecord>,
    payload_control_hash: Option<String>,
    outbound_payload_sent: bool,
    delivered_payloads: usize,
    profile_verifications: usize,
    terminal: Option<TerminalReason>,
    local_decline_committed: bool,
    terminal_replay_frame_digest: Option<[u8; 32]>,
}

impl fmt::Debug for EndpointReducer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointReducer")
            .field("side", &self.side)
            .field("application", &self.application)
            .field("ceremony", &self.ceremony)
            .field("invitation_status", &self.record.status)
            .field("session_ready", &self.session.is_some())
            .field("terminal", &self.terminal)
            .field("secret_state", &"[REDACTED]")
            .finish()
    }
}

impl EndpointReducer {
    /// Compose the cryptographic and CBCL components for one bound attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        side: Side,
        invitation: &[u8],
        record: InvitationRecord,
        ceremony_key: CeremonySigningKey,
        bootstrap: BootstrapMonitor,
        pending_channel: PendingChannel,
        allocator_cpace_hash: String,
        claimant_cpace_hash: String,
        profile: Box<dyn ApplicationProfile>,
    ) -> Result<Self, ReducerError> {
        let invitation_digest: [u8; 32] = Sha256::digest(invitation).into();
        if record.status != InvitationStatus::Bound || record.invitation_digest != invitation_digest
        {
            return Err(ReducerError::Invitation);
        }
        let mut invitation_value =
            decode_invitation(invitation).map_err(|_| ReducerError::Recognition)?;
        let application = invitation_value.application.clone();
        let expected_role_keys = [
            invitation_value.expected_allocator_key,
            invitation_value.expected_claimant_key,
        ];
        if profile.recognise_invitation(&invitation_value).is_err() {
            invitation_value.secret.zeroize();
            return Err(ReducerError::Profile);
        }
        invitation_value.secret.zeroize();
        let mut endpoint = Self {
            side,
            application,
            ceremony: ceremony_id(invitation),
            expected_role_keys,
            profile,
            record,
            ceremony_key: Some(ceremony_key),
            bootstrap: Some(bootstrap),
            pending_channel: Some(pending_channel),
            channel: None,
            session: None,
            allocator_cpace_hash,
            claimant_cpace_hash,
            local_finished: None,
            pending_finished: None,
            pending_applications: Vec::new(),
            intent: None,
            decision: None,
            payload_control_hash: None,
            outbound_payload_sent: false,
            delivered_payloads: 0,
            profile_verifications: 0,
            terminal: None,
            local_decline_committed: false,
            terminal_replay_frame_digest: None,
        };
        endpoint.validate_expected_role_keys()?;
        Ok(endpoint)
    }

    /// Admit a CPace control into the bootstrap history without applying crypto.
    pub fn admit_bootstrap_control(
        &mut self,
        performative: BootstrapPerformative,
        control: &[u8],
        body: &[u8],
    ) -> Result<ProtocolVerdict, ReducerError> {
        self.ensure_live()?;
        let result =
            self.bootstrap
                .as_mut()
                .ok_or(ReducerError::Phase)?
                .admit(performative, control, body);
        match result {
            Ok(admission) if admission.verdict() != ProtocolVerdict::Violation => {
                self.validate_expected_role_keys()?;
                Ok(admission.verdict())
            }
            Ok(_) | Err(_) => self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol),
        }
    }

    /// Build and admit this endpoint's Finished frame.
    ///
    /// Returns `None` when CBCL reports `Unknown`; no cryptographic state or
    /// externally visible effect changes in that case.
    pub fn local_finished_frame(&mut self) -> Result<Option<ChannelFrame>, ReducerError> {
        self.ensure_live()?;
        self.validate_expected_role_keys()?;
        if let Some(frame) = &self.local_finished {
            return Ok(Some(frame.clone()));
        }
        let value = self
            .pending_channel
            .as_ref()
            .ok_or(ReducerError::Phase)?
            .local_finished();
        let performative = match self.side {
            Side::Allocator => BootstrapPerformative::FinishedA,
            Side::Claimant => BootstrapPerformative::FinishedB,
        };
        let key = self.ceremony_key.as_ref().ok_or(ReducerError::Phase)?;
        let control = build_bootstrap_control(
            key,
            performative,
            &self.ceremony,
            &value,
            CausedBy::Multiple(vec![
                self.allocator_cpace_hash.clone(),
                self.claimant_cpace_hash.clone(),
            ]),
        )
        .map_err(|_| ReducerError::Protocol)?;
        let admission = match self.bootstrap.as_mut().ok_or(ReducerError::Phase)?.admit(
            performative,
            &control,
            &value,
        ) {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol),
        };
        match admission.verdict() {
            ProtocolVerdict::Unknown => Ok(None),
            ProtocolVerdict::Violation => {
                self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol)
            }
            ProtocolVerdict::Valid => {
                let frame = ChannelFrame::Finished {
                    side: self.side,
                    control,
                    value,
                };
                self.local_finished = Some(frame.clone());
                Ok(Some(frame))
            }
        }
    }

    /// Receive a peer Finished or sealed frame and emit only authorised effects.
    pub fn receive_frame(
        &mut self,
        frame: &ChannelFrame,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.terminal.is_some() {
            if self.terminal == Some(TerminalReason::Declined)
                && self.terminal_replay_frame_digest == channel_frame_digest(frame).ok()
            {
                return Ok(Vec::new());
            }
            return Err(ReducerError::Terminal);
        }
        self.ensure_live()?;
        match frame {
            ChannelFrame::Finished { .. } => self.receive_finished(frame),
            ChannelFrame::Sealed { .. } => self.receive_sealed(frame),
            ChannelFrame::Cpace { .. } => {
                self.fail(TerminalReason::ProtocolViolation, ReducerError::Phase)
            }
        }
    }

    /// Retry one exact peer Finished control retained after an `Unknown`
    /// verdict. This remains effect-free while unresolved.
    pub fn retry_pending_finished(&mut self) -> Result<Vec<EndpointEffect>, ReducerError> {
        self.ensure_live()?;
        match self.pending_finished.clone() {
            Some(frame) => self.receive_finished(&frame),
            None => Ok(Vec::new()),
        }
    }

    /// Construct and seal the allocator's first application intent.
    pub fn send_intent(&mut self, intent: &PairingIntent) -> Result<ChannelFrame, ReducerError> {
        self.ensure_live()?;
        if self.side != Side::Allocator || self.intent.is_some() {
            return Err(ReducerError::Phase);
        }
        if intent.application != self.application {
            return self.fail(TerminalReason::IntentMismatch, ReducerError::IntentDigest);
        }
        let (_, profile_binding) = self
            .profile
            .recognise_intent(intent)
            .map_err(|_| ReducerError::Profile)?
            .into_parts();
        let body = encode_pairing_intent(intent).map_err(|_| ReducerError::Recognition)?;
        let digest = Sha256::digest(&body).into();
        let root = self
            .session
            .as_ref()
            .ok_or(ReducerError::Phase)?
            .root_hash()
            .to_owned();
        let claimant = self.role_key(PairingRole::Claimant)?;
        let control = build_session_control(
            self.ceremony_key.as_ref().ok_or(ReducerError::Phase)?,
            SessionPerformative::Intent,
            &self.ceremony,
            &claimant,
            &body,
            CausedBy::Single(root),
        )
        .map_err(|_| ReducerError::Protocol)?;
        let admission = self.admit_local_session(SessionPerformative::Intent, &control, &body)?;
        let frame = self.seal_control(control, Some(body))?;
        self.intent = Some(IntentRecord {
            digest,
            control_hash: admission,
            profile_binding,
        });
        Ok(frame)
    }

    /// Commit and transmit the claimant's explicit decision.
    pub fn decide(&mut self, decision: Decision) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.terminal.is_some() {
            if self.terminal == Some(TerminalReason::Declined)
                && self.local_decline_committed
                && decision == Decision::Decline
            {
                return Ok(Vec::new());
            }
            return Err(ReducerError::Terminal);
        }
        self.ensure_live()?;
        if self.side != Side::Claimant {
            return Err(ReducerError::Phase);
        }
        if let Some(existing) = &self.decision {
            if existing.decision == decision {
                return Ok(Vec::new());
            }
            return self.fail(
                TerminalReason::DecisionConflict,
                ReducerError::DecisionConflict,
            );
        }
        let intent = self.intent.clone().ok_or(ReducerError::Phase)?;
        let body = encode_pairing_decision(&PairingDecision {
            intent_digest: intent.digest,
            decision,
        })
        .map_err(|_| ReducerError::Recognition)?;
        let allocator = self.role_key(PairingRole::Allocator)?;
        let performative = match decision {
            Decision::Approve => SessionPerformative::Approve,
            Decision::Decline => SessionPerformative::Decline,
        };
        let control = build_session_control(
            self.ceremony_key.as_ref().ok_or(ReducerError::Phase)?,
            performative,
            &self.ceremony,
            &allocator,
            &body,
            CausedBy::Single(intent.control_hash),
        )
        .map_err(|_| ReducerError::Protocol)?;
        let control_hash = self.admit_local_session(performative, &control, &body)?;
        let frame = self.seal_control(control, Some(body))?;
        self.decision = Some(DecisionRecord {
            decision,
            control_hash,
        });
        if decision == Decision::Decline {
            self.local_decline_committed = true;
            self.terminate(TerminalReason::Declined);
            Ok(vec![
                EndpointEffect::SendFrame(frame),
                EndpointEffect::CloseMailbox,
            ])
        } else {
            Ok(vec![EndpointEffect::SendFrame(frame)])
        }
    }

    /// Construct and seal one application payload after approval.
    pub fn send_payload(
        &mut self,
        payload: &ApplicationPayload,
    ) -> Result<ChannelFrame, ReducerError> {
        self.ensure_live()?;
        if self.side != Side::Allocator {
            return Err(ReducerError::Phase);
        }
        let intent = self.intent.clone().ok_or(ReducerError::Phase)?;
        let decision = self.decision.clone().ok_or(ReducerError::Phase)?;
        if decision.decision != Decision::Approve {
            return Err(ReducerError::Phase);
        }
        if payload.intent_digest != intent.digest {
            return Err(ReducerError::IntentDigest);
        }
        if self.outbound_payload_sent {
            return Err(ReducerError::Phase);
        }
        self.profile
            .recognise_payload(&intent.profile_binding, payload)
            .map_err(|_| ReducerError::Profile)?;
        let body = encode_application_payload(payload).map_err(|_| ReducerError::Recognition)?;
        let claimant = self.role_key(PairingRole::Claimant)?;
        let control = build_session_control(
            self.ceremony_key.as_ref().ok_or(ReducerError::Phase)?,
            SessionPerformative::Payload,
            &self.ceremony,
            &claimant,
            &body,
            CausedBy::Single(decision.control_hash),
        )
        .map_err(|_| ReducerError::Protocol)?;
        self.admit_local_session(SessionPerformative::Payload, &control, &body)?;
        let frame = self.seal_control(control, Some(body))?;
        self.outbound_payload_sent = true;
        Ok(frame)
    }

    /// Return the durable invitation status.
    #[must_use]
    pub fn invitation_status(&self) -> InvitationStatus {
        self.record.status()
    }

    /// Return the terminal classification, if any.
    #[must_use]
    pub fn terminal_reason(&self) -> Option<TerminalReason> {
        self.terminal
    }

    /// Whether all secret-bearing cryptographic components have been dropped.
    #[must_use]
    pub fn secrets_erased(&self) -> bool {
        self.ceremony_key.is_none() && self.pending_channel.is_none() && self.channel.is_none()
    }

    /// Whether the role cast has been admitted after key confirmation.
    #[must_use]
    pub fn session_ready(&self) -> bool {
        self.session.is_some()
    }

    /// Digest of the accepted intent, without retaining its display metadata.
    #[must_use]
    pub fn intent_digest(&self) -> Option<[u8; 32]> {
        self.intent.as_ref().map(|value| value.digest)
    }

    /// Number of application payloads released to the profile.
    #[must_use]
    pub fn delivered_payloads(&self) -> usize {
        self.delivered_payloads
    }

    /// Number of payloads passed to the application grant verifier.
    #[must_use]
    pub fn profile_verifications(&self) -> usize {
        self.profile_verifications
    }

    fn receive_finished(
        &mut self,
        frame: &ChannelFrame,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        let ChannelFrame::Finished {
            side,
            control,
            value,
        } = frame
        else {
            unreachable!("dispatched by receive_frame")
        };
        if *side == self.side {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::WrongSide);
        }
        if self.local_finished.is_none() {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Phase);
        }
        self.validate_expected_role_keys()?;
        let expected = match side {
            Side::Allocator => BootstrapPerformative::FinishedA,
            Side::Claimant => BootstrapPerformative::FinishedB,
        };
        let admission = match self
            .bootstrap
            .as_mut()
            .ok_or(ReducerError::Phase)?
            .admit(expected, control, value)
        {
            Ok(admission) => admission,
            Err(_) => return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol),
        };
        match admission.verdict() {
            ProtocolVerdict::Unknown => {
                if self
                    .pending_finished
                    .as_ref()
                    .is_some_and(|pending| pending != frame)
                {
                    return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
                }
                self.pending_finished = Some(frame.clone());
                Ok(Vec::new())
            }
            ProtocolVerdict::Violation => {
                self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol)
            }
            ProtocolVerdict::Valid => {
                self.pending_finished = None;
                let pending = self.pending_channel.take().ok_or(ReducerError::Phase)?;
                let channel = match pending.confirm(value) {
                    Ok(channel) => channel,
                    Err(_) => {
                        return self.fail(TerminalReason::KeyConfirmation, ReducerError::Channel)
                    }
                };
                self.channel = Some(channel);
                self.record.spend();
                if self.side == Side::Allocator {
                    self.open_allocator_session()
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    fn open_allocator_session(&mut self) -> Result<Vec<EndpointEffect>, ReducerError> {
        let allocator = self.role_key(PairingRole::Allocator)?;
        let claimant = self.role_key(PairingRole::Claimant)?;
        let opener = build_session_opener(
            self.ceremony_key.as_ref().ok_or(ReducerError::Phase)?,
            &claimant,
            &self.ceremony,
        )
        .map_err(|_| ReducerError::Protocol)?;
        let (session, admission) = SessionMonitor::open_for_ceremony(
            &self.ceremony,
            PairingRole::Allocator,
            &allocator,
            &claimant,
            &opener,
        )
        .map_err(|_| ReducerError::Protocol)?;
        if admission.verdict() != ProtocolVerdict::Valid {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        self.session = Some(session);
        let frame = self.seal_control(opener, None)?;
        Ok(vec![EndpointEffect::SendFrame(frame)])
    }

    fn receive_sealed(
        &mut self,
        frame: &ChannelFrame,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        let frame_digest = channel_frame_digest(frame)?;
        let plaintext_bytes = match self
            .channel
            .as_mut()
            .ok_or(ReducerError::Phase)?
            .open(frame)
        {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::Channel, ReducerError::Channel),
        };
        let plaintext = match decode_sealed_plaintext(&plaintext_bytes) {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::Malformed, ReducerError::Recognition),
        };
        if self.session.is_none() {
            return self.receive_opener(plaintext);
        }
        let body = match plaintext.body.as_deref() {
            Some(value) => value,
            None => return self.fail(TerminalReason::Malformed, ReducerError::Recognition),
        };
        let decoded = match decode_application(body) {
            Ok(value) => value,
            Err(error) => return self.fail(TerminalReason::Malformed, error),
        };
        let result = self.admit_application(plaintext, decoded);
        if result.is_ok() && self.terminal == Some(TerminalReason::Declined) {
            self.terminal_replay_frame_digest = Some(frame_digest);
        }
        result
    }

    fn receive_opener(
        &mut self,
        plaintext: SealedPlaintext,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.side != Side::Claimant || plaintext.body.is_some() {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        let allocator = self.role_key(PairingRole::Allocator)?;
        let claimant = self.role_key(PairingRole::Claimant)?;
        let (session, admission) = match SessionMonitor::open_for_ceremony(
            &self.ceremony,
            PairingRole::Claimant,
            &allocator,
            &claimant,
            &plaintext.control,
        ) {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol),
        };
        if admission.verdict() != ProtocolVerdict::Valid {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        self.session = Some(session);
        Ok(Vec::new())
    }

    fn admit_application(
        &mut self,
        plaintext: SealedPlaintext,
        decoded: DecodedApplication,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        let body = plaintext.body.as_deref().ok_or(ReducerError::Recognition)?;
        let performative = decoded.performative();
        let admission = match self.session.as_mut().ok_or(ReducerError::Phase)?.admit(
            performative,
            &plaintext.control,
            body,
        ) {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol),
        };
        match admission.verdict() {
            ProtocolVerdict::Violation => {
                self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol)
            }
            ProtocolVerdict::Unknown => {
                let pending = PendingApplication { plaintext, decoded };
                if !self.pending_applications.contains(&pending) {
                    if self.pending_applications.len() == MAX_PENDING_CONTROLS {
                        return self
                            .fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
                    }
                    self.pending_applications.push(pending);
                }
                Ok(Vec::new())
            }
            ProtocolVerdict::Valid => {
                let mut effects = self.apply_application(decoded, admission.content_hash())?;
                effects.extend(self.retry_pending()?);
                Ok(effects)
            }
        }
    }

    fn retry_pending(&mut self) -> Result<Vec<EndpointEffect>, ReducerError> {
        let mut emitted = Vec::new();
        let mut remaining = std::mem::take(&mut self.pending_applications);
        let mut progress = true;
        while progress {
            progress = false;
            let mut next = Vec::new();
            for pending in remaining {
                let body = pending
                    .plaintext
                    .body
                    .as_deref()
                    .ok_or(ReducerError::Recognition)?;
                let admission = self
                    .session
                    .as_mut()
                    .ok_or(ReducerError::Phase)?
                    .admit(
                        pending.decoded.performative(),
                        &pending.plaintext.control,
                        body,
                    )
                    .map_err(|_| ReducerError::Protocol)?;
                match admission.verdict() {
                    ProtocolVerdict::Unknown => next.push(pending),
                    ProtocolVerdict::Violation => {
                        self.pending_applications = next;
                        return self
                            .fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
                    }
                    ProtocolVerdict::Valid => {
                        emitted.extend(
                            self.apply_application(pending.decoded, admission.content_hash())?,
                        );
                        progress = true;
                    }
                }
            }
            remaining = next;
        }
        self.pending_applications = remaining;
        Ok(emitted)
    }

    fn apply_application(
        &mut self,
        decoded: DecodedApplication,
        control_hash: &str,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        match decoded {
            DecodedApplication::Intent(value) => self.apply_intent(value, control_hash),
            DecodedApplication::Decision(value) => self.apply_decision(value, control_hash),
            DecodedApplication::Payload(value) => self.apply_payload(value, control_hash),
        }
    }

    fn apply_intent(
        &mut self,
        value: PairingIntent,
        control_hash: &str,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.side != Side::Claimant || value.application != self.application {
            return self.fail(TerminalReason::IntentMismatch, ReducerError::IntentDigest);
        }
        let encoded = encode_pairing_intent(&value).map_err(|_| ReducerError::Recognition)?;
        let digest = Sha256::digest(encoded).into();
        let (display, profile_binding) = match self.profile.recognise_intent(&value) {
            Ok(value) => value.into_parts(),
            Err(_) => return self.fail(TerminalReason::Profile, ReducerError::Profile),
        };
        if let Some(existing) = &self.intent {
            if existing.digest == digest && existing.control_hash == control_hash {
                return Ok(Vec::new());
            }
            return self.fail(TerminalReason::IntentMismatch, ReducerError::IntentDigest);
        }
        self.intent = Some(IntentRecord {
            digest,
            control_hash: control_hash.into(),
            profile_binding,
        });
        Ok(vec![EndpointEffect::DisplayIntent(display)])
    }

    fn apply_decision(
        &mut self,
        value: PairingDecision,
        control_hash: &str,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.side != Side::Allocator {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        let intent = self.intent.as_ref().ok_or(ReducerError::Phase)?;
        if value.intent_digest != intent.digest {
            return self.fail(TerminalReason::IntentMismatch, ReducerError::IntentDigest);
        }
        if let Some(existing) = &self.decision {
            if existing.decision == value.decision && existing.control_hash == control_hash {
                return Ok(Vec::new());
            }
            return self.fail(
                TerminalReason::DecisionConflict,
                ReducerError::DecisionConflict,
            );
        }
        self.decision = Some(DecisionRecord {
            decision: value.decision,
            control_hash: control_hash.into(),
        });
        if value.decision == Decision::Decline {
            self.terminate(TerminalReason::Declined);
            Ok(vec![EndpointEffect::CloseMailbox])
        } else {
            Ok(Vec::new())
        }
    }

    fn apply_payload(
        &mut self,
        value: ApplicationPayload,
        control_hash: &str,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        if self.side != Side::Claimant {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        let intent = self.intent.as_ref().ok_or(ReducerError::Phase)?;
        if value.intent_digest != intent.digest
            || self.decision.as_ref().map(|item| item.decision) != Some(Decision::Approve)
        {
            return self.fail(TerminalReason::IntentMismatch, ReducerError::IntentDigest);
        }
        if let Some(existing) = &self.payload_control_hash {
            if existing == control_hash {
                return Ok(Vec::new());
            }
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        let recognised = match self
            .profile
            .recognise_payload(&intent.profile_binding, &value)
        {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::Profile, ReducerError::Profile),
        };
        self.profile_verifications += 1;
        let grant = match self.profile.authorize_payload(recognised) {
            Ok(value) => value,
            Err(_) => return self.fail(TerminalReason::Profile, ReducerError::Profile),
        };
        self.payload_control_hash = Some(control_hash.into());
        self.delivered_payloads += 1;
        Ok(vec![EndpointEffect::DeliverGrant(grant)])
    }

    fn admit_local_session(
        &mut self,
        performative: SessionPerformative,
        control: &[u8],
        body: &[u8],
    ) -> Result<String, ReducerError> {
        let admission = self
            .session
            .as_mut()
            .ok_or(ReducerError::Phase)?
            .admit(performative, control, body)
            .map_err(|_| ReducerError::Protocol)?;
        if admission.verdict() != ProtocolVerdict::Valid {
            return self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol);
        }
        Ok(admission.content_hash().into())
    }

    fn seal_control(
        &mut self,
        control: Vec<u8>,
        body: Option<Vec<u8>>,
    ) -> Result<ChannelFrame, ReducerError> {
        let plaintext = encode_sealed_plaintext(&SealedPlaintext { control, body })
            .map_err(|_| ReducerError::Recognition)?;
        let result = self
            .channel
            .as_mut()
            .ok_or(ReducerError::Phase)?
            .seal(&plaintext);
        match result {
            Ok(frame) => Ok(frame),
            Err(_) => self.fail(TerminalReason::Channel, ReducerError::Channel),
        }
    }

    fn role_key(&self, role: PairingRole) -> Result<CeremonyKeyId, ReducerError> {
        self.bootstrap
            .as_ref()
            .and_then(|monitor| monitor.role_key(role))
            .cloned()
            .ok_or(ReducerError::Phase)
    }

    fn validate_expected_role_keys(&mut self) -> Result<(), ReducerError> {
        let mismatch = [PairingRole::Allocator, PairingRole::Claimant]
            .into_iter()
            .enumerate()
            .any(|(index, role)| {
                let Some(expected) = self.expected_role_keys[index] else {
                    return false;
                };
                let Some(actual) = self
                    .bootstrap
                    .as_ref()
                    .and_then(|monitor| monitor.role_key(role))
                else {
                    return false;
                };
                actual
                    .public_key_bytes()
                    .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)))
                    != Ok(expected)
            });
        if mismatch {
            self.fail(TerminalReason::ProtocolViolation, ReducerError::Protocol)
        } else {
            Ok(())
        }
    }

    fn ensure_live(&self) -> Result<(), ReducerError> {
        if self.terminal.is_some() {
            Err(ReducerError::Terminal)
        } else {
            Ok(())
        }
    }

    fn fail<T>(&mut self, reason: TerminalReason, error: ReducerError) -> Result<T, ReducerError> {
        self.terminate(reason);
        Err(error)
    }

    fn terminate(&mut self, reason: TerminalReason) {
        self.terminal = Some(reason);
        self.record.spend();
        self.ceremony_key = None;
        self.pending_channel = None;
        self.channel = None;
        self.bootstrap = None;
        self.session = None;
        self.local_finished = None;
        self.pending_finished = None;
        self.pending_applications.clear();
        self.intent = None;
        self.decision = None;
        self.payload_control_hash = None;
        self.outbound_payload_sent = false;
    }
}

fn attempt_binding(
    invitation_digest: &[u8; 32],
    mailbox_id: &[u8; 32],
    peer_cpace_frame: &[u8],
    public_context: &[u8],
) -> Result<[u8; 32], ReducerError> {
    let value = Value::Array(vec![
        Value::Text("blind-pairing-attempt/v1".into()),
        Value::Bytes(invitation_digest.to_vec()),
        Value::Bytes(mailbox_id.to_vec()),
        Value::Bytes(peer_cpace_frame.to_vec()),
        Value::Bytes(public_context.to_vec()),
    ]);
    let encoded = cbor2::to_canonical_vec(&value).map_err(|_| ReducerError::Recognition)?;
    Ok(Sha256::digest(encoded).into())
}

fn channel_frame_digest(frame: &ChannelFrame) -> Result<[u8; 32], ReducerError> {
    let encoded = encode_channel_frame(frame).map_err(|_| ReducerError::Recognition)?;
    Ok(Sha256::digest(encoded).into())
}

fn decode_application(body: &[u8]) -> Result<DecodedApplication, ReducerError> {
    if let Ok(value) = decode_pairing_intent(body) {
        return Ok(DecodedApplication::Intent(value));
    }
    if let Ok(value) = decode_pairing_decision(body) {
        return Ok(DecodedApplication::Decision(value));
    }
    if let Ok(value) = decode_application_payload(body) {
        return Ok(DecodedApplication::Payload(value));
    }
    Err(ReducerError::Recognition)
}
