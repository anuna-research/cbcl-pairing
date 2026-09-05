use super::{
    decode_frame, decode_object, encode_frame, CredentialV2Advance, CredentialV2BodyVerifier,
    CredentialV2Carrier, CredentialV2CheckpointNonce, CredentialV2Context, CredentialV2Endpoint,
    CredentialV2Error, CredentialV2Frame, CredentialV2Kind, CredentialV2Phase,
    CredentialV2Presence, CredentialV2PresenceCode, CredentialV2RecoveredReceiptAuthority,
    CredentialV2RelayState, EndpointCheckpointV2, PendingCredentialV2Channel,
    SecureCredentialV2Channel,
};
use crate::{
    cpace,
    wire::{
        decode_server_message, encode_client_message, ClaimToken, ClientMessage, ServerMessage,
        Side,
    },
};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Inputs held by one wallet-side credential/v2 claimant before socket creation.
///
/// This intentionally contains no custody-derived checkpoint key. Current law
/// first permits that key after final approval, while this session is
/// restart-abandonable until then.
pub struct CredentialV2ClaimantSessionInput {
    /// Independently recognised public machine carrier.
    pub carrier: CredentialV2Carrier,
    /// Separately typed, manually entered human-presence value.
    pub presence_code: CredentialV2PresenceCode,
    /// Fresh claimant CPace scalar.
    pub cpace_scalar: [u8; 32],
    /// Digest of the live independently authenticated application profile.
    pub profile_digest: [u8; 32],
}

/// Selfsame-owned verification bridge for the allocator's first signed offer.
pub trait CredentialV2ClaimantOfferVerifier: fmt::Debug + Send {
    /// Verify the signed offer against live authority by invoking the endpoint's
    /// dedicated authenticated-display transition.
    fn verify_offer(
        &mut self,
        endpoint: &mut CredentialV2Endpoint,
        object: &super::CredentialV2Object,
        now: u64,
    ) -> Result<CredentialV2Advance, CredentialV2Error>;
}

/// One claimant effect whose external ordering belongs to the wallet shell.
pub enum CredentialV2ClaimantEffect {
    /// Send one canonical client-to-relay message.
    Send(Vec<u8>),
    /// Durably replace the pending claimant checkpoint before any later effect.
    Checkpoint {
        /// Exact monotonically increasing checkpoint generation.
        generation: u64,
        /// Opaque sealed endpoint checkpoint.
        checkpoint: EndpointCheckpointV2,
    },
    /// CPace and both Finished values established one peer-bound channel.
    ///
    /// The shell must commit or confirm exact-pair policy and then call
    /// [`CredentialV2ClaimantSession::authorise_authenticated_profile`] before
    /// any offer can be accepted.
    Established {
        /// Exact 64-octet transcript hash.
        transcript_hash: [u8; 64],
    },
    /// Display only the Selfsame-verified, authenticated private intent.
    DisplayIntent(Box<super::CredentialV2Display>),
    /// One authenticated peer successor advanced the memory-only endpoint.
    ReceivedObject {
        /// Fully recognised padded object and its exact logical body.
        object: super::CredentialV2Object,
    },
    /// Relay or protocol termination before completion.
    Terminal,
}

/// One authenticated receipt frame withheld from the relay acknowledgement.
///
/// The value is intentionally non-cloneable and its recovery authority remains
/// private. A wallet may inspect [`Self::object`] and verify its application
/// final status, but only the claimant session that opened the frame can consume
/// the value through [`CredentialV2ClaimantSession::commit_recovered_receipt`].
pub struct CredentialV2ClaimantRecoveredReceipt {
    object: super::CredentialV2Object,
    authority: CredentialV2RecoveredReceiptAuthority,
    peer_seq: Option<u8>,
}

impl CredentialV2ClaimantRecoveredReceipt {
    /// Borrow the endpoint-authenticated Receipt object for application checks.
    #[must_use]
    pub const fn object(&self) -> &super::CredentialV2Object {
        &self.object
    }
}

impl fmt::Debug for CredentialV2ClaimantRecoveredReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialV2ClaimantRecoveredReceipt([AUTHENTICATED])")
    }
}

impl fmt::Debug for CredentialV2ClaimantEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(bytes) => formatter.debug_tuple("Send").field(&bytes.len()).finish(),
            Self::Checkpoint {
                generation,
                checkpoint,
            } => formatter
                .debug_struct("Checkpoint")
                .field("generation", generation)
                .field("checkpoint_bytes", &checkpoint.as_bytes().len())
                .finish(),
            Self::Established { transcript_hash } => formatter
                .debug_struct("Established")
                .field("transcript_hash", &transcript_hash.as_slice())
                .finish(),
            Self::DisplayIntent(_) => formatter.write_str("DisplayIntent([AUTHENTICATED])"),
            Self::ReceivedObject { object } => formatter
                .debug_struct("ReceivedObject")
                .field("kind", &object.kind())
                .field("body_bytes", &object.body().len())
                .finish(),
            Self::Terminal => formatter.write_str("Terminal"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimantPhase {
    AwaitWelcome,
    ClaimSent,
    ShareSent,
    FinishedSent,
    AwaitProfileAuthorisation,
    Established,
    Terminal,
}

/// Relay-driven credential/v2 claimant through authenticated offer display.
///
/// All state in this type is memory-only. A restart before final approval
/// abandons the ceremony. Durable claimant checkpoints begin only at the
/// endpoint's final-approval boundary.
pub struct CredentialV2ClaimantSession {
    carrier: CredentialV2Carrier,
    presence: Option<CredentialV2Presence>,
    claim_token: Option<ClaimToken>,
    cpace_scalar: Zeroizing<[u8; 32]>,
    profile_digest: [u8; 32],
    phase: ClaimantPhase,
    relay: Option<CredentialV2RelayState>,
    local_share: Option<CredentialV2Frame>,
    peer_share: Option<CredentialV2Frame>,
    pending_channel: Option<PendingCredentialV2Channel>,
    peer_finished: Option<CredentialV2Frame>,
    endpoint: Option<Box<CredentialV2Endpoint>>,
    channel: Option<Box<SecureCredentialV2Channel>>,
    body_verifier: Option<Box<dyn CredentialV2BodyVerifier>>,
    offer_verifier: Option<Box<dyn CredentialV2ClaimantOfferVerifier>>,
    authenticated_offer: Option<super::CredentialV2Object>,
    persistence_gate: Option<u64>,
    after_persist: Vec<CredentialV2ClaimantEffect>,
    pending_recovered_receipt: bool,
}

impl fmt::Debug for CredentialV2ClaimantSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialV2ClaimantSession([REDACTED])")
    }
}

impl CredentialV2ClaimantSession {
    /// Validate one claimant attempt without opening a relay connection.
    pub fn new(
        input: CredentialV2ClaimantSessionInput,
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<Self, CredentialV2Error> {
        CredentialV2Context::derive(&input.carrier, input.profile_digest)?;
        Ok(Self {
            carrier: input.carrier,
            presence: Some(input.presence_code.into_presence()),
            claim_token: None,
            cpace_scalar: Zeroizing::new(input.cpace_scalar),
            profile_digest: input.profile_digest,
            phase: ClaimantPhase::AwaitWelcome,
            relay: None,
            local_share: None,
            peer_share: None,
            pending_channel: None,
            peer_finished: None,
            endpoint: None,
            channel: None,
            body_verifier: Some(body_verifier),
            offer_verifier: None,
            authenticated_offer: None,
            persistence_gate: None,
            after_persist: Vec::new(),
            pending_recovered_receipt: false,
        })
    }

    /// Restore only a post-final claimant endpoint from an exact sealed
    /// checkpoint. Preliminary decisions and display authority are never
    /// reconstructed by this path.
    pub fn restore(
        checkpoint: &[u8],
        wrapping_key: &[u8; 32],
        carrier: CredentialV2Carrier,
        expected_generation: u64,
        now: u64,
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<Self, CredentialV2Error> {
        let restored = CredentialV2Endpoint::restore_checkpoint(
            checkpoint,
            wrapping_key,
            Side::Claimant,
            &carrier,
            expected_generation,
            now,
            body_verifier,
        )?;
        let (endpoint, channel, relay) = restored.into_parts();
        if !matches!(
            endpoint.phase(),
            CredentialV2Phase::FinalApproved | CredentialV2Phase::PayloadSent
        ) {
            return Err(CredentialV2Error::Phase);
        }
        Ok(Self {
            carrier,
            presence: None,
            claim_token: None,
            cpace_scalar: Zeroizing::new([0; 32]),
            profile_digest: [0; 32],
            phase: ClaimantPhase::Established,
            relay: Some(relay),
            local_share: None,
            peer_share: None,
            pending_channel: None,
            peer_finished: None,
            endpoint: Some(Box::new(endpoint)),
            channel: Some(Box::new(channel)),
            body_verifier: None,
            offer_verifier: None,
            authenticated_offer: None,
            persistence_gate: None,
            after_persist: Vec::new(),
            pending_recovered_receipt: false,
        })
    }

    /// Return the first version-binding relay frame.
    pub fn start(&self) -> Result<Vec<u8>, CredentialV2Error> {
        if self.phase != ClaimantPhase::AwaitWelcome {
            return Err(CredentialV2Error::Phase);
        }
        relay_message(ClientMessage::Bind)
    }

    /// Apply one complete relay response while the carrier remains live.
    pub fn receive(
        &mut self,
        input: &[u8],
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some() || self.has_durable_endpoint_phase() {
            return Err(CredentialV2Error::Phase);
        }
        if self.phase == ClaimantPhase::Terminal {
            return Err(CredentialV2Error::Terminal);
        }
        if now >= self.carrier.relay_expires_at() {
            self.terminate();
            return Err(CredentialV2Error::Expired);
        }
        let result = decode_server_message(input)
            .map_err(|_| CredentialV2Error::Schema)
            .and_then(|message| self.apply_server(message, now));
        if result.is_err() {
            self.terminate();
        }
        result
    }

    /// Confirm that the peer-bound profile and any newly approved exact-pair
    /// policy are ready. No offer frame is accepted before this gate.
    pub fn authorise_authenticated_profile(
        &mut self,
        offer_verifier: Box<dyn CredentialV2ClaimantOfferVerifier>,
    ) -> Result<(), CredentialV2Error> {
        if self.phase != ClaimantPhase::AwaitProfileAuthorisation {
            return Err(CredentialV2Error::Phase);
        }
        self.offer_verifier = Some(offer_verifier);
        self.phase = ClaimantPhase::Established;
        Ok(())
    }

    /// Borrow the exact signed-offer body only after authenticated display.
    #[must_use]
    pub fn authenticated_offer_body(&self) -> Option<&[u8]> {
        self.authenticated_offer
            .as_ref()
            .map(|object| object.body())
    }

    /// Borrow the complete authenticated Offer object for exact successor
    /// construction after the person sees its typed display.
    #[must_use]
    pub const fn authenticated_offer(&self) -> Option<&super::CredentialV2Object> {
        self.authenticated_offer.as_ref()
    }

    /// Report whether one exact application frame is still awaiting its relay
    /// acknowledgement. This exposes no frame or bearer bytes.
    #[must_use]
    pub fn has_cached_outbound_frame(&self) -> bool {
        self.relay
            .as_ref()
            .and_then(CredentialV2RelayState::cached_outbound_frame)
            .is_some()
    }

    /// Return the public receipt-recovery commitment from the claimant's
    /// established channel. The recovery token itself never leaves the core.
    pub fn receipt_recovery_commitment(&self) -> Result<[u8; 32], CredentialV2Error> {
        if self.phase != ClaimantPhase::Established {
            return Err(CredentialV2Error::Phase);
        }
        let endpoint = self.endpoint.as_ref().ok_or(CredentialV2Error::Phase)?;
        self.channel
            .as_ref()
            .ok_or(CredentialV2Error::Phase)?
            .receipt_recovery_commitment(&endpoint.carrier)
    }

    /// Use the secret receipt-recovery token only while a restored or live
    /// claimant is durably waiting for its terminal Receipt.
    ///
    /// The token is derived into zeroizing storage and borrowed only for the
    /// duration of `consumer`. This deliberately has no WASM binding: a native
    /// protocol shell may encode the closed HTTPS recovery request, while
    /// browser script can obtain only [`Self::receipt_recovery_commitment`].
    pub fn with_receipt_recovery_token<T>(
        &self,
        consumer: impl FnOnce(&[u8; 32]) -> T,
    ) -> Result<T, CredentialV2Error> {
        if self.phase != ClaimantPhase::Established
            || self.endpoint_phase()? != CredentialV2Phase::PayloadSent
        {
            return Err(CredentialV2Error::Phase);
        }
        let token = self
            .channel
            .as_ref()
            .ok_or(CredentialV2Error::Phase)?
            .receipt_recovery_token()?;
        Ok(consumer(&token))
    }

    /// Report the sole post-Finished point where the consumer may commit a
    /// newly approved exact-pair policy row.
    #[must_use]
    pub const fn is_awaiting_profile_authorisation(&self) -> bool {
        matches!(self.phase, ClaimantPhase::AwaitProfileAuthorisation)
    }

    /// Seal one pre-final claimant object without creating durable authority.
    ///
    /// Final approval and payload are deliberately absent from this API. They
    /// require the claimant checkpoint barrier and a custody-derived wrapping
    /// key supplied only after the corresponding person decision.
    pub fn prepare_application_object(
        &mut self,
        object: &super::CredentialV2Object,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || !matches!(
                object.kind(),
                CredentialV2Kind::IntentApprove
                    | CredentialV2Kind::IntentDecline
                    | CredentialV2Kind::Preparation
                    | CredentialV2Kind::Refusal
                    | CredentialV2Kind::FinalDecline
            )
        {
            return Err(CredentialV2Error::Phase);
        }
        let endpoint = self.endpoint.as_mut().ok_or(CredentialV2Error::Phase)?;
        let channel = self.channel.as_mut().ok_or(CredentialV2Error::Phase)?;
        let relay = self.relay.as_mut().ok_or(CredentialV2Error::Phase)?;
        let frame = endpoint.prepare_outbound(object, channel, relay)?;
        let sequence = relay.cached_application_sequence()?;
        Ok(vec![CredentialV2ClaimantEffect::Send(relay_message(
            ClientMessage::Put {
                seq: sequence,
                body: encode_frame(&frame)?,
            },
        )?)])
    }

    /// Advance through final approval, then expose only the checkpoint that
    /// must join the consumer's sealed pending slot before frame release.
    pub fn prepare_final_approval(
        &mut self,
        object: &super::CredentialV2Object,
        wrapping_key: &[u8; 32],
        nonce: CredentialV2CheckpointNonce,
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || !self.after_persist.is_empty()
            || self.phase != ClaimantPhase::Established
            || object.kind() != CredentialV2Kind::FinalApprove
        {
            return Err(CredentialV2Error::Phase);
        }
        let result = (|| {
            let endpoint = self.endpoint.as_mut().ok_or(CredentialV2Error::Phase)?;
            let channel = self.channel.as_mut().ok_or(CredentialV2Error::Phase)?;
            let relay = self.relay.as_mut().ok_or(CredentialV2Error::Phase)?;
            let frame = endpoint.prepare_outbound(object, channel, relay)?;
            let sequence = relay.cached_application_sequence()?;
            let generation = endpoint.checkpoint_generation.saturating_add(1);
            let checkpoint = endpoint.seal_checkpoint(
                channel,
                relay,
                wrapping_key,
                generation,
                Some(self.carrier.relay_expires_at()),
                nonce,
                now,
            )?;
            self.persistence_gate = Some(generation);
            self.after_persist = vec![CredentialV2ClaimantEffect::Send(relay_message(
                ClientMessage::Put {
                    seq: sequence,
                    body: encode_frame(&frame)?,
                },
            )?)];
            Ok(vec![CredentialV2ClaimantEffect::Checkpoint {
                generation,
                checkpoint,
            }])
        })();
        if result.is_err() {
            self.terminate();
        }
        result
    }

    /// Confirm atomic pending-slot storage and release only its covered frame.
    pub fn checkpoint_persisted(
        &mut self,
        generation: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate != Some(generation) {
            return Err(CredentialV2Error::Counter);
        }
        self.persistence_gate = None;
        Ok(std::mem::take(&mut self.after_persist))
    }

    /// Re-emit only the exact frame already covered by the restored durable
    /// checkpoint. An empty cache produces no effect.
    pub fn resume_cached_frame(
        &mut self,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || !self.has_durable_endpoint_phase()
        {
            return Err(CredentialV2Error::Phase);
        }
        let relay = self.relay.as_ref().ok_or(CredentialV2Error::Phase)?;
        let Some(frame) = relay.cached_outbound_frame() else {
            return Ok(Vec::new());
        };
        let sequence = relay.cached_application_sequence()?;
        Ok(vec![CredentialV2ClaimantEffect::Send(relay_message(
            ClientMessage::Put {
                seq: sequence,
                body: encode_frame(frame)?,
            },
        )?)])
    }

    /// Apply an acknowledgement after final approval and checkpoint the
    /// updated cached-frame projection before exposing another effect.
    pub fn receive_durable(
        &mut self,
        input: &[u8],
        now: u64,
        wrapping_key: &[u8; 32],
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || !self.has_durable_endpoint_phase()
        {
            return Err(CredentialV2Error::Phase);
        }
        let endpoint_phase = self.endpoint_phase()?;
        if endpoint_phase == CredentialV2Phase::FinalApproved
            && now >= self.carrier.relay_expires_at()
        {
            return Err(CredentialV2Error::Expired);
        }
        let ServerMessage::Acknowledged { seq } =
            decode_server_message(input).map_err(|_| CredentialV2Error::Schema)?
        else {
            return Err(CredentialV2Error::Phase);
        };
        if self.relay_ref()?.acknowledgement_already_applied(seq) {
            // Existing persistence/phase and pre-payload expiry gates above
            // still apply. No new checkpoint, generation or nonce is consumed.
            return Ok(Vec::new());
        }
        self.local_ack(seq)?;
        let expiry = match endpoint_phase {
            CredentialV2Phase::FinalApproved => Some(self.carrier.relay_expires_at()),
            CredentialV2Phase::PayloadSent => None,
            _ => return Err(CredentialV2Error::Phase),
        };
        self.checkpoint_current(wrapping_key, nonce, now, expiry, Vec::new())
    }

    /// Open and authenticate the sole post-payload Receipt without releasing
    /// its relay acknowledgement or advancing the terminal endpoint edge.
    ///
    /// This split lets the wallet verify the application-signed final status,
    /// observe reciprocal WebFinger, and durably install the grant first. A
    /// malformed or unauthenticated frame terminates this in-memory session;
    /// the last durable payload checkpoint remains the recovery authority.
    pub fn receive_recovered_receipt(
        &mut self,
        input: &[u8],
    ) -> Result<CredentialV2ClaimantRecoveredReceipt, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || self.endpoint_phase()? != CredentialV2Phase::PayloadSent
            || self.pending_recovered_receipt
            || self.has_cached_outbound_frame()
        {
            return Err(CredentialV2Error::Phase);
        }
        let result = (|| {
            let ServerMessage::Frame { peer_seq, body } =
                decode_server_message(input).map_err(|_| CredentialV2Error::Schema)?
            else {
                return Err(CredentialV2Error::Phase);
            };
            let frame = decode_frame(&body)?;
            self.relay_mut()?.accept_peer_sequence(peer_seq)?;
            let plaintext = self
                .channel
                .as_mut()
                .ok_or(CredentialV2Error::Phase)?
                .open(&frame)?;
            let object = decode_object(&plaintext)?;
            let authority = self
                .endpoint
                .as_mut()
                .ok_or(CredentialV2Error::Phase)?
                .authenticate_recovered_receipt(&object)?;
            Ok(CredentialV2ClaimantRecoveredReceipt {
                object,
                authority,
                peer_seq: Some(peer_seq),
            })
        })();
        match result {
            Ok(receipt) => {
                self.pending_recovered_receipt = true;
                Ok(receipt)
            }
            Err(error) => {
                self.terminate();
                Err(error)
            }
        }
    }

    /// Authenticate the exact Receipt reconstructed from an HTTPS recovery
    /// status without inventing a relay frame or acknowledgement.
    ///
    /// The registered body verifier and endpoint predecessor checks are the
    /// same ones used by [`Self::receive_recovered_receipt`]. A refusal leaves
    /// the restored payload checkpoint live for a later authenticated retry.
    pub fn authenticate_recovered_receipt_object(
        &mut self,
        object: super::CredentialV2Object,
    ) -> Result<CredentialV2ClaimantRecoveredReceipt, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || self.endpoint_phase()? != CredentialV2Phase::PayloadSent
            || self.pending_recovered_receipt
        {
            return Err(CredentialV2Error::Phase);
        }
        let authority = self
            .endpoint
            .as_mut()
            .ok_or(CredentialV2Error::Phase)?
            .authenticate_recovered_receipt(&object)?;
        self.pending_recovered_receipt = true;
        Ok(CredentialV2ClaimantRecoveredReceipt {
            object,
            authority,
            peer_seq: None,
        })
    }

    /// Consume one authenticated Receipt only after the wallet's installed
    /// state is durable, then release the exact relay acknowledgement.
    pub fn commit_recovered_receipt(
        &mut self,
        receipt: CredentialV2ClaimantRecoveredReceipt,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if !self.pending_recovered_receipt
            || self.persistence_gate.is_some()
            || self.phase != ClaimantPhase::Established
            || self.endpoint_phase()? != CredentialV2Phase::PayloadSent
            || (receipt.peer_seq.is_some() && self.has_cached_outbound_frame())
        {
            return Err(CredentialV2Error::Phase);
        }
        let acknowledgement = receipt
            .peer_seq
            .map(|peer_seq| relay_message(ClientMessage::Ack { peer_seq }))
            .transpose()?;
        self.endpoint
            .as_mut()
            .ok_or(CredentialV2Error::Phase)?
            .recover_receipt(&receipt.object, receipt.authority)?;
        self.pending_recovered_receipt = false;
        self.terminate();
        Ok(acknowledgement
            .map(CredentialV2ClaimantEffect::Send)
            .into_iter()
            .collect())
    }

    /// Report whether a verified Receipt is waiting on the consumer's durable
    /// install boundary.
    #[must_use]
    pub const fn has_pending_recovered_receipt(&self) -> bool {
        self.pending_recovered_receipt
    }

    /// Seal and retain the reverse payload under a null-expiry checkpoint
    /// before releasing its exact cached frame.
    pub fn prepare_payload(
        &mut self,
        object: &super::CredentialV2Object,
        wrapping_key: &[u8; 32],
        nonce: CredentialV2CheckpointNonce,
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some()
            || !self.after_persist.is_empty()
            || self.phase != ClaimantPhase::Established
            || self.endpoint_phase()? != CredentialV2Phase::FinalApproved
            || object.kind() != CredentialV2Kind::Payload
        {
            return Err(CredentialV2Error::Phase);
        }
        if now >= self.carrier.relay_expires_at() {
            return Err(CredentialV2Error::Expired);
        }
        let result = (|| {
            let endpoint = self.endpoint.as_mut().ok_or(CredentialV2Error::Phase)?;
            let channel = self.channel.as_mut().ok_or(CredentialV2Error::Phase)?;
            let relay = self.relay.as_mut().ok_or(CredentialV2Error::Phase)?;
            let frame = endpoint.prepare_outbound(object, channel, relay)?;
            let sequence = relay.cached_application_sequence()?;
            let after = vec![CredentialV2ClaimantEffect::Send(relay_message(
                ClientMessage::Put {
                    seq: sequence,
                    body: encode_frame(&frame)?,
                },
            )?)];
            self.checkpoint_current(wrapping_key, nonce, now, None, after)
        })();
        if result.is_err() {
            self.terminate();
        }
        result
    }

    fn checkpoint_current(
        &mut self,
        wrapping_key: &[u8; 32],
        nonce: CredentialV2CheckpointNonce,
        now: u64,
        expiry: Option<u64>,
        after: Vec<CredentialV2ClaimantEffect>,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some() || !self.after_persist.is_empty() {
            return Err(CredentialV2Error::Phase);
        }
        let endpoint = self.endpoint.as_mut().ok_or(CredentialV2Error::Phase)?;
        let channel = self.channel.as_ref().ok_or(CredentialV2Error::Phase)?;
        let relay = self.relay.as_ref().ok_or(CredentialV2Error::Phase)?;
        let generation = endpoint.checkpoint_generation.saturating_add(1);
        let checkpoint = endpoint.seal_checkpoint(
            channel,
            relay,
            wrapping_key,
            generation,
            expiry,
            nonce,
            now,
        )?;
        self.persistence_gate = Some(generation);
        self.after_persist = after;
        Ok(vec![CredentialV2ClaimantEffect::Checkpoint {
            generation,
            checkpoint,
        }])
    }

    fn endpoint_phase(&self) -> Result<CredentialV2Phase, CredentialV2Error> {
        self.endpoint
            .as_ref()
            .map(|endpoint| endpoint.phase())
            .ok_or(CredentialV2Error::Phase)
    }

    fn has_durable_endpoint_phase(&self) -> bool {
        self.endpoint.as_ref().is_some_and(|endpoint| {
            matches!(
                endpoint.phase(),
                CredentialV2Phase::FinalApproved | CredentialV2Phase::PayloadSent
            )
        })
    }

    fn apply_server(
        &mut self,
        message: ServerMessage,
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        match message {
            ServerMessage::Welcome if self.phase == ClaimantPhase::AwaitWelcome => {
                let claim_token = self
                    .presence
                    .as_mut()
                    .ok_or(CredentialV2Error::Phase)?
                    .take_claim_token()?;
                self.claim_token = Some(claim_token.clone());
                self.phase = ClaimantPhase::ClaimSent;
                Ok(vec![CredentialV2ClaimantEffect::Send(relay_message(
                    ClientMessage::ClaimV2 {
                        mailbox_id: *self.carrier.mailbox_id(),
                        claim_token,
                    },
                )?)])
            }
            ServerMessage::ClaimedV2 {
                mailbox_id,
                membership_token,
                expires_at,
            } if self.phase == ClaimantPhase::ClaimSent => {
                self.claimed(mailbox_id, membership_token, expires_at)
            }
            ServerMessage::Frame { peer_seq, body } => self.peer_frame(peer_seq, &body, now),
            ServerMessage::Acknowledged { seq } => self.local_ack(seq),
            ServerMessage::Pong => Ok(Vec::new()),
            ServerMessage::Closed(_) | ServerMessage::Error(_) => {
                self.terminate();
                Ok(vec![CredentialV2ClaimantEffect::Terminal])
            }
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn claimed(
        &mut self,
        mailbox_id: [u8; 32],
        membership_token: [u8; 32],
        expires_at: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if mailbox_id != *self.carrier.mailbox_id() || expires_at != self.carrier.relay_expires_at()
        {
            return Err(CredentialV2Error::Profile);
        }
        self.claim_token = None;
        let context = CredentialV2Context::derive(&self.carrier, self.profile_digest)?;
        let (_, share) = context.start_cpace(
            Side::Claimant,
            self.presence.as_ref().ok_or(CredentialV2Error::Phase)?,
            *self.cpace_scalar,
        )?;
        let share = CredentialV2Frame::cpace(&share)?;
        let mut relay = CredentialV2RelayState::new(membership_token);
        let sequence = relay.queue_bootstrap_frame()?;
        self.local_share = Some(share.clone());
        self.relay = Some(relay);
        self.phase = ClaimantPhase::ShareSent;
        Ok(vec![CredentialV2ClaimantEffect::Send(relay_message(
            ClientMessage::Put {
                seq: sequence,
                body: encode_frame(&share)?,
            },
        )?)])
    }

    fn peer_frame(
        &mut self,
        peer_seq: u8,
        body: &[u8],
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        let frame = decode_frame(body)?;
        if self.phase == ClaimantPhase::Established {
            return self.peer_application_frame(peer_seq, frame, now);
        }
        self.relay_mut()?.accept_peer_sequence(peer_seq)?;
        let ack = CredentialV2ClaimantEffect::Send(relay_message(ClientMessage::Ack { peer_seq })?);
        match self.phase {
            ClaimantPhase::ShareSent => {
                if frame.cpace_message().map(|value| value.side) != Some(Side::Allocator) {
                    return Err(CredentialV2Error::Direction);
                }
                self.peer_share = Some(frame);
                if self.relay_ref()?.awaiting_ack() {
                    Ok(vec![ack])
                } else {
                    let put = self.prepare_finished()?;
                    Ok(vec![ack, put])
                }
            }
            ClaimantPhase::FinishedSent => {
                if frame.finished().map(|value| value.0) != Some(Side::Allocator) {
                    return Err(CredentialV2Error::Direction);
                }
                self.peer_finished = Some(frame);
                if self.relay_ref()?.awaiting_ack() {
                    Ok(vec![ack])
                } else {
                    self.establish(Some(ack))
                }
            }
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn local_ack(
        &mut self,
        sequence: u8,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        if self.relay_ref()?.acknowledgement_already_applied(sequence) {
            return Ok(Vec::new());
        }
        if self.phase == ClaimantPhase::Established {
            self.relay_mut()?.acknowledge_application_frame(sequence)?;
            return Ok(Vec::new());
        }
        self.relay_mut()?.acknowledge_bootstrap_frame(sequence)?;
        match self.phase {
            ClaimantPhase::ShareSent if self.peer_share.is_some() => {
                Ok(vec![self.prepare_finished()?])
            }
            ClaimantPhase::ShareSent | ClaimantPhase::FinishedSent
                if self.peer_finished.is_none() =>
            {
                Ok(Vec::new())
            }
            ClaimantPhase::FinishedSent => self.establish(None),
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn prepare_finished(&mut self) -> Result<CredentialV2ClaimantEffect, CredentialV2Error> {
        let context = CredentialV2Context::derive(&self.carrier, self.profile_digest)?;
        let (state, local_message) = context.start_cpace(
            Side::Claimant,
            self.presence.as_ref().ok_or(CredentialV2Error::Phase)?,
            *self.cpace_scalar,
        )?;
        let local_share = CredentialV2Frame::cpace(&local_message)?;
        if self.local_share.as_ref() != Some(&local_share) {
            return Err(CredentialV2Error::Profile);
        }
        let peer_share = self.peer_share.as_ref().ok_or(CredentialV2Error::Phase)?;
        let peer_message = peer_share
            .cpace_message()
            .ok_or(CredentialV2Error::Schema)?;
        let isk = cpace::finish(state, peer_message).map_err(|_| CredentialV2Error::Cpace)?;
        let pending = PendingCredentialV2Channel::new(
            Side::Claimant,
            isk,
            context.public_context(),
            &encode_frame(peer_share)?,
            &encode_frame(&local_share)?,
        )?;
        let finished = pending.local_finished_frame();
        let sequence = self.relay_mut()?.queue_bootstrap_frame()?;
        self.pending_channel = Some(pending);
        self.phase = ClaimantPhase::FinishedSent;
        Ok(CredentialV2ClaimantEffect::Send(relay_message(
            ClientMessage::Put {
                seq: sequence,
                body: encode_frame(&finished)?,
            },
        )?))
    }

    fn establish(
        &mut self,
        ack: Option<CredentialV2ClaimantEffect>,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        let peer_finished = self
            .peer_finished
            .as_ref()
            .ok_or(CredentialV2Error::Finished)?;
        let channel = self
            .pending_channel
            .take()
            .ok_or(CredentialV2Error::Phase)?
            .confirm(peer_finished)?;
        if self.relay_ref()?.awaiting_ack() {
            return Err(CredentialV2Error::Phase);
        }
        let transcript_hash = channel.transcript_hash();
        self.endpoint = Some(Box::new(CredentialV2Endpoint::new(
            Side::Claimant,
            self.carrier.clone(),
            self.body_verifier.take().ok_or(CredentialV2Error::Phase)?,
        )));
        self.channel = Some(Box::new(channel));
        self.phase = ClaimantPhase::AwaitProfileAuthorisation;
        self.presence = None;
        self.cpace_scalar.zeroize();
        self.local_share = None;
        self.peer_share = None;
        self.peer_finished = None;
        let mut effects = Vec::new();
        if let Some(ack) = ack {
            effects.push(ack);
        }
        effects.push(CredentialV2ClaimantEffect::Established { transcript_hash });
        Ok(effects)
    }

    fn peer_application_frame(
        &mut self,
        peer_seq: u8,
        frame: CredentialV2Frame,
        now: u64,
    ) -> Result<Vec<CredentialV2ClaimantEffect>, CredentialV2Error> {
        self.relay_mut()?.accept_peer_sequence(peer_seq)?;
        let plaintext = self
            .channel
            .as_mut()
            .ok_or(CredentialV2Error::Phase)?
            .open(&frame)?;
        let object = decode_object(&plaintext)?;
        let endpoint = self.endpoint.as_mut().ok_or(CredentialV2Error::Phase)?;
        let advance = if endpoint.phase() == CredentialV2Phase::Begin {
            if object.kind() != CredentialV2Kind::Offer {
                return Err(CredentialV2Error::Phase);
            }
            self.offer_verifier
                .as_mut()
                .ok_or(CredentialV2Error::Phase)?
                .verify_offer(endpoint, &object, now)?
        } else {
            endpoint.receive(&object)?
        };
        let mut effects = vec![CredentialV2ClaimantEffect::Send(relay_message(
            ClientMessage::Ack { peer_seq },
        )?)];
        match advance {
            CredentialV2Advance::DisplayIntent(display) => {
                self.authenticated_offer = Some(object);
                effects.push(CredentialV2ClaimantEffect::DisplayIntent(display));
            }
            CredentialV2Advance::Advanced => {
                effects.push(CredentialV2ClaimantEffect::ReceivedObject { object });
            }
            CredentialV2Advance::ExactRetransmission => {}
        }
        Ok(effects)
    }

    fn relay_ref(&self) -> Result<&CredentialV2RelayState, CredentialV2Error> {
        self.relay.as_ref().ok_or(CredentialV2Error::Phase)
    }

    fn relay_mut(&mut self) -> Result<&mut CredentialV2RelayState, CredentialV2Error> {
        self.relay.as_mut().ok_or(CredentialV2Error::Phase)
    }

    fn terminate(&mut self) {
        self.phase = ClaimantPhase::Terminal;
        self.presence = None;
        self.claim_token = None;
        self.cpace_scalar.zeroize();
        self.local_share = None;
        self.peer_share = None;
        self.pending_channel = None;
        self.peer_finished = None;
        self.endpoint = None;
        self.channel = None;
        self.relay = None;
        self.authenticated_offer = None;
        self.persistence_gate = None;
        self.after_persist.clear();
        self.pending_recovered_receipt = false;
    }
}

fn relay_message(message: ClientMessage) -> Result<Vec<u8>, CredentialV2Error> {
    encode_client_message(&message).map_err(|_| CredentialV2Error::Schema)
}
