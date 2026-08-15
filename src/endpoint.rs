//! Security-state reducer composed around the CBCL protocol monitors.
//!
//! CBCL owns legal predecessors and role directions. This reducer owns only
//! invitation consumption, cryptographic activation/erasure, decision
//! uniqueness, and application-effect release.

use crate::{
    cbcl_protocol::{BootstrapMonitor, BootstrapPerformative, CeremonySigningKey, ProtocolVerdict},
    channel::PendingChannel,
    wire::{ApplicationPayload, ChannelFrame, PairingIntent, Side},
};

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
pub struct InvitationRecord;

impl InvitationRecord {
    /// Create an unused record for exact invitation bytes.
    #[must_use]
    pub fn new(_invitation: &[u8]) -> Self {
        Self
    }

    /// Atomically bind the invitation before processing a peer CPace frame.
    pub fn bind(
        &mut self,
        _mailbox_id: [u8; 32],
        _peer_cpace_frame: &[u8],
        _public_context: &[u8],
    ) -> Result<BindOutcome, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Return the durable status.
    #[must_use]
    pub fn status(&self) -> InvitationStatus {
        InvitationStatus::Unused
    }
}

/// Observable effect emitted only after all preceding gates pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointEffect {
    /// Transmit one already protected pairing-channel frame.
    SendFrame(ChannelFrame),
    /// Display a fully recognised, channel-authenticated pairing intent.
    DisplayIntent(PairingIntent),
    /// Deliver one approved, digest-bound application payload to its profile.
    DeliverPayload(ApplicationPayload),
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
    /// Temporary Red Gate sentinel.
    NotImplemented,
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
    /// Both decision siblings were observed.
    DecisionConflict,
    /// The reducer is already terminal.
    Terminal,
}

/// Reducer for one endpoint after local CPace computation has begun.
pub struct EndpointReducer;

impl EndpointReducer {
    /// Compose the cryptographic and CBCL components for one bound attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _side: Side,
        _invitation: &[u8],
        _record: InvitationRecord,
        _ceremony_key: CeremonySigningKey,
        _bootstrap: BootstrapMonitor,
        _pending_channel: PendingChannel,
        _allocator_cpace_hash: String,
        _claimant_cpace_hash: String,
    ) -> Result<Self, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Admit a CPace control into the bootstrap history without applying crypto.
    pub fn admit_bootstrap_control(
        &mut self,
        _performative: BootstrapPerformative,
        _control: &[u8],
        _body: &[u8],
    ) -> Result<ProtocolVerdict, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Build and admit this endpoint's Finished frame.
    ///
    /// Returns `None` when CBCL reports `Unknown`; no cryptographic state or
    /// externally visible effect changes in that case.
    pub fn local_finished_frame(&mut self) -> Result<Option<ChannelFrame>, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Receive a peer Finished or sealed frame and emit only authorised effects.
    pub fn receive_frame(
        &mut self,
        _frame: &ChannelFrame,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Construct and seal the allocator's first application intent.
    pub fn send_intent(&mut self, _intent: &PairingIntent) -> Result<ChannelFrame, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Commit and transmit the claimant's explicit decision.
    pub fn decide(
        &mut self,
        _decision: crate::wire::Decision,
    ) -> Result<Vec<EndpointEffect>, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Construct and seal one application payload after approval.
    pub fn send_payload(
        &mut self,
        _payload: &ApplicationPayload,
    ) -> Result<ChannelFrame, ReducerError> {
        Err(ReducerError::NotImplemented)
    }

    /// Return the durable invitation status.
    #[must_use]
    pub fn invitation_status(&self) -> InvitationStatus {
        InvitationStatus::Unused
    }

    /// Return the terminal classification, if any.
    #[must_use]
    pub fn terminal_reason(&self) -> Option<TerminalReason> {
        None
    }

    /// Whether all secret-bearing cryptographic components have been dropped.
    #[must_use]
    pub fn secrets_erased(&self) -> bool {
        false
    }

    /// Whether the role cast has been admitted after key confirmation.
    #[must_use]
    pub fn session_ready(&self) -> bool {
        false
    }

    /// Digest of the accepted intent, without retaining its display metadata.
    #[must_use]
    pub fn intent_digest(&self) -> Option<[u8; 32]> {
        None
    }

    /// Number of application payloads released to the profile.
    #[must_use]
    pub fn delivered_payloads(&self) -> usize {
        0
    }
}
