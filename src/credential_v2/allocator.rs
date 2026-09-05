use super::{
    decode_frame, decode_object, encode_carrier, CredentialV2AllocatorBootstrap,
    CredentialV2AllocatorBootstrapPhase, CredentialV2AllocatorMode, CredentialV2BodyVerifier,
    CredentialV2Carrier, CredentialV2CarrierInput, CredentialV2CheckpointNonce,
    CredentialV2Endpoint, CredentialV2Error, CredentialV2Object, CredentialV2Presence,
    CredentialV2RelayState, EndpointCheckpointV2, SecureCredentialV2Channel,
};
use crate::wire::{
    claim_commitment, decode_server_message, encode_client_message, ClaimToken, ClientMessage,
    ServerMessage, Side,
};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Exact caller-owned values for one protected credential/v2 allocation.
pub struct CredentialV2AllocatorSessionInput {
    /// Explicit transfer mode. Never inferred from `cpace_secret` bytes.
    pub mode: CredentialV2AllocatorMode,
    /// Canonical application identifier bound into CPace.
    pub application_context: String,
    /// Canonical protected relay origin.
    pub relay_origin: String,
    /// Fresh direct mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Fresh sole ceremony identifier.
    pub carrier_ceremony_id: [u8; 32],
    /// Fresh carrier nonce.
    pub carrier_nonce: [u8; 32],
    /// Separate human CPace secret `C`.
    pub cpace_secret: [u8; 16],
    /// Separate one-use relay claim token `T`.
    pub claim_token: [u8; 16],
    /// Fresh allocator CPace scalar.
    pub cpace_scalar: [u8; 32],
    /// Digest of the independently authenticated live profile.
    pub profile_digest: [u8; 32],
    /// Optional expected allocator ceremony key.
    pub expected_allocator_key: Option<[u8; 32]>,
    /// Browser-derived key that seals every allocator checkpoint.
    pub checkpoint_wrapping_key: [u8; 32],
}

/// One effect whose ordering remains the browser shell's responsibility.
pub enum CredentialV2AllocatorEffect {
    /// Send one canonical client-to-relay message.
    Send(Vec<u8>),
    /// Durably replace the allocator checkpoint before asking for another effect.
    Checkpoint {
        /// Exact monotonically increasing checkpoint generation.
        generation: u64,
        /// Opaque sealed endpoint checkpoint.
        checkpoint: EndpointCheckpointV2,
        /// Recognised carrier needed to bind restoration and derive its key.
        carrier: Vec<u8>,
    },
    /// Ask the authenticated application session to allocate pending authority.
    PendingAllocation {
        /// Exact machine carrier; this is not yet public display authority.
        carrier: Vec<u8>,
    },
    /// CPace and both Finished values established one protected channel.
    Established {
        /// Exact 64-octet credential/v2 transcript hash.
        transcript_hash: [u8; 64],
    },
    /// One authenticated peer object advanced the endpoint after durable state.
    ReceivedObject {
        /// Fully recognised padded object and its exact logical body.
        object: CredentialV2Object,
    },
    /// The relay ended before application completion.
    Terminal,
}

impl fmt::Debug for CredentialV2AllocatorEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(bytes) => formatter.debug_tuple("Send").field(&bytes.len()).finish(),
            Self::Checkpoint {
                generation,
                checkpoint,
                carrier,
            } => formatter
                .debug_struct("Checkpoint")
                .field("generation", generation)
                .field("checkpoint_bytes", &checkpoint.as_bytes().len())
                .field("carrier_bytes", &carrier.len())
                .finish(),
            Self::PendingAllocation { carrier } => formatter
                .debug_struct("PendingAllocation")
                .field("carrier_bytes", &carrier.len())
                .finish(),
            Self::Established { transcript_hash } => formatter
                .debug_struct("Established")
                .field("transcript_hash", &transcript_hash.as_slice())
                .finish(),
            Self::ReceivedObject { object } => formatter
                .debug_struct("ReceivedObject")
                .field("kind", &object.kind())
                .field("body_bytes", &object.body().len())
                .finish(),
            Self::Terminal => formatter.write_str("Terminal"),
        }
    }
}

enum AllocatorState {
    AwaitWelcome,
    AwaitAllocation,
    Bootstrap(Box<CredentialV2AllocatorBootstrap>),
    Established {
        endpoint: Box<CredentialV2Endpoint>,
        channel: Box<SecureCredentialV2Channel>,
        relay: Box<CredentialV2RelayState>,
    },
    Terminal,
}

/// Relay-driven credential/v2 allocator with an explicit persistence barrier.
pub struct CredentialV2AllocatorSession {
    template: CredentialV2Carrier,
    presence: Option<CredentialV2Presence>,
    cpace_scalar: Option<Zeroizing<[u8; 32]>>,
    mode: CredentialV2AllocatorMode,
    profile_digest: [u8; 32],
    claim_commitment: [u8; 32],
    wrapping_key: Zeroizing<[u8; 32]>,
    body_verifier: Option<Box<dyn CredentialV2BodyVerifier>>,
    state: AllocatorState,
    persistence_gate: Option<u64>,
    after_persist: Vec<CredentialV2AllocatorEffect>,
    resume_after_welcome: bool,
}

impl fmt::Debug for CredentialV2AllocatorSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialV2AllocatorSession([REDACTED])")
    }
}

impl CredentialV2AllocatorSession {
    /// Validate one attempt before any relay bytes are released.
    pub fn new(
        input: CredentialV2AllocatorSessionInput,
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<Self, CredentialV2Error> {
        if input.mode == CredentialV2AllocatorMode::Manual {
            super::CredentialV2ManualWords::from_secret(input.cpace_secret)
                .map_err(|_| CredentialV2Error::Schema)?;
            if input.expected_allocator_key.is_none() {
                return Err(CredentialV2Error::Profile);
            }
        }
        let claim = ClaimToken::new(input.claim_token);
        let commitment = claim_commitment(input.mailbox_id, &claim);
        let template = CredentialV2Carrier::new(CredentialV2CarrierInput {
            application_context: input.application_context,
            relay_origin: input.relay_origin,
            mailbox_id: input.mailbox_id,
            carrier_ceremony_id: input.carrier_ceremony_id,
            carrier_nonce: input.carrier_nonce,
            claim_commitment: commitment,
            relay_expires_at: u64::MAX,
            expected_allocator_key: input.expected_allocator_key,
        })?;
        Ok(Self {
            template,
            presence: Some(CredentialV2Presence::new(
                input.cpace_secret,
                input.claim_token,
            )),
            cpace_scalar: Some(Zeroizing::new(input.cpace_scalar)),
            mode: input.mode,
            profile_digest: input.profile_digest,
            claim_commitment: commitment,
            wrapping_key: Zeroizing::new(input.checkpoint_wrapping_key),
            body_verifier: Some(body_verifier),
            state: AllocatorState::AwaitWelcome,
            persistence_gate: None,
            after_persist: Vec::new(),
            resume_after_welcome: false,
        })
    }

    /// Restore an allocator bootstrap or established endpoint from one exact
    /// sealed checkpoint. Caller-held carrier, generation, profile digest and
    /// wrapping key are all mandatory bindings. Bootstrap mode must match its
    /// authenticated tag (old v2 means Full). Established state has no mode.
    /// `fresh_cpace_scalar` must be fresh shell CSPRNG output; it is retained
    /// only before the first peer. Bound checkpoints use their retained scalar.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        checkpoint: &[u8],
        wrapping_key: &[u8; 32],
        carrier: CredentialV2Carrier,
        expected_generation: u64,
        expected_profile_digest: [u8; 32],
        now: u64,
        expected_mode: CredentialV2AllocatorMode,
        fresh_cpace_scalar: [u8; 32],
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<Self, CredentialV2Error> {
        let fresh_cpace_scalar = Zeroizing::new(fresh_cpace_scalar);
        if let Ok(bootstrap) = CredentialV2AllocatorBootstrap::restore_checkpoint(
            checkpoint,
            wrapping_key,
            &carrier,
            expected_generation,
            now,
            expected_mode,
        ) {
            if bootstrap.profile_digest() != &expected_profile_digest {
                return Err(CredentialV2Error::Profile);
            }
            return Ok(Self {
                template: carrier.clone(),
                presence: None,
                cpace_scalar: (bootstrap.phase() == CredentialV2AllocatorBootstrapPhase::Allocated)
                    .then(|| Zeroizing::new(*fresh_cpace_scalar)),
                mode: expected_mode,
                profile_digest: expected_profile_digest,
                claim_commitment: *carrier.claim_commitment(),
                wrapping_key: Zeroizing::new(*wrapping_key),
                body_verifier: Some(body_verifier),
                state: AllocatorState::Bootstrap(Box::new(bootstrap)),
                persistence_gate: None,
                after_persist: Vec::new(),
                resume_after_welcome: true,
            });
        }

        let restored = CredentialV2Endpoint::restore_checkpoint(
            checkpoint,
            wrapping_key,
            Side::Allocator,
            &carrier,
            expected_generation,
            now,
            body_verifier,
        )?;
        let (endpoint, channel, relay) = restored.into_parts();
        Ok(Self {
            template: carrier.clone(),
            presence: None,
            cpace_scalar: None,
            mode: expected_mode,
            profile_digest: expected_profile_digest,
            claim_commitment: *carrier.claim_commitment(),
            wrapping_key: Zeroizing::new(*wrapping_key),
            body_verifier: None,
            state: AllocatorState::Established {
                endpoint: Box::new(endpoint),
                channel: Box::new(channel),
                relay: Box::new(relay),
            },
            persistence_gate: None,
            after_persist: Vec::new(),
            resume_after_welcome: true,
        })
    }

    /// First canonical relay binding frame.
    pub fn start(&self) -> Result<Vec<u8>, CredentialV2Error> {
        if (!matches!(self.state, AllocatorState::AwaitWelcome) && !self.resume_after_welcome)
            || self.persistence_gate.is_some()
        {
            return Err(CredentialV2Error::Phase);
        }
        relay_message(ClientMessage::Bind)
    }

    /// Return the public Selfsame receipt-recovery commitment after both
    /// Finished values are verified.
    ///
    /// The HMAC token and exporter remain inside Rust and the sealed endpoint
    /// checkpoint. Only this SHA-256 commitment may cross into browser script.
    pub fn receipt_recovery_commitment(&self) -> Result<[u8; 32], CredentialV2Error> {
        match &self.state {
            AllocatorState::Established {
                endpoint, channel, ..
            } => channel.receipt_recovery_commitment(&endpoint.carrier),
            _ => Err(CredentialV2Error::Phase),
        }
    }

    /// Return the restored or live endpoint phase after Finished.
    #[must_use]
    pub fn endpoint_phase(&self) -> Option<super::CredentialV2Phase> {
        match &self.state {
            AllocatorState::Established { endpoint, .. } => Some(endpoint.phase()),
            _ => None,
        }
    }

    /// Return the restored bootstrap phase before Finished establishes the
    /// protected application channel.
    #[must_use]
    pub fn bootstrap_phase(&self) -> Option<super::CredentialV2AllocatorBootstrapPhase> {
        match &self.state {
            AllocatorState::Bootstrap(bootstrap) => Some(bootstrap.phase()),
            _ => None,
        }
    }

    /// Return mode only while the bootstrap retains its authenticated authority.
    /// Established state cannot authenticate or export a bootstrap mode.
    #[must_use]
    pub fn bootstrap_mode(&self) -> Option<CredentialV2AllocatorMode> {
        match &self.state {
            AllocatorState::Bootstrap(bootstrap) => Some(bootstrap.mode()),
            _ => None,
        }
    }

    /// Reconstruct the human-presence code only while its one-use claim token
    /// remains inside a restored bootstrap checkpoint.
    pub fn presence_code(&self) -> Option<String> {
        match &self.state {
            AllocatorState::Bootstrap(bootstrap) => bootstrap.presence_code(),
            _ => None,
        }
    }

    /// Export the exact retained carrier and presence for confidential local transfer.
    /// Returns `None` before relay allocation, after claim admission, or when closed.
    /// The shell controls display timing after checkpoint and application commits,
    /// and clears displayed text at the retained carrier's original expiry.
    pub fn handoff_text(&self) -> Result<Option<Zeroizing<String>>, CredentialV2Error> {
        let AllocatorState::Bootstrap(bootstrap) = &self.state else {
            return Ok(None);
        };
        bootstrap
            .handoff()?
            .map(|handoff| handoff.encode().map_err(|_| CredentialV2Error::Schema))
            .transpose()
    }

    /// Export manual bootstrap and words only from a Manual bootstrap with live T.
    /// The shell uses private callbacks after its durable allocation and hub commits,
    /// and clears both values at the earlier authenticated hub/relay expiry.
    /// Full mode refuses; pre-allocation, consumed, established and closed return None.
    #[allow(clippy::type_complexity)] // Two zeroizing transfer strings; no additional container.
    pub fn manual_transfer_text(
        &self,
    ) -> Result<Option<(Zeroizing<String>, Zeroizing<String>)>, CredentialV2Error> {
        match &self.state {
            AllocatorState::Bootstrap(bootstrap) => bootstrap.manual_transfer_text(),
            _ => Ok(None),
        }
    }

    /// Return the protected channel transcript after Finished.
    #[must_use]
    pub fn transcript_hash(&self) -> Option<[u8; 64]> {
        match &self.state {
            AllocatorState::Established { channel, .. } => Some(channel.transcript_hash()),
            _ => None,
        }
    }

    /// Reconstruct only the exact last authenticated peer object retained by
    /// the endpoint checkpoint. Locally authored objects are not presented as
    /// received input.
    pub fn last_received_object(&self) -> Result<Option<CredentialV2Object>, CredentialV2Error> {
        let AllocatorState::Established { endpoint, .. } = &self.state else {
            return Ok(None);
        };
        let Some(last) = endpoint.last.as_ref() else {
            return Ok(None);
        };
        if last.sender == Side::Allocator {
            return Ok(None);
        }
        last.bytes.as_deref().map(decode_object).transpose()
    }

    /// Apply one complete relay response. A checkpoint effect is always alone.
    pub fn receive(
        &mut self,
        input: &[u8],
        now: u64,
        checkpoint_nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some() {
            return Err(CredentialV2Error::Phase);
        }
        let result = decode_server_message(input)
            .map_err(|_| CredentialV2Error::Schema)
            .and_then(|message| self.apply_server(message, now, checkpoint_nonce));
        if result.is_err() {
            self.terminate();
        }
        result
    }

    /// Confirm durable storage and release only the effects covered by it.
    pub fn checkpoint_persisted(
        &mut self,
        generation: u64,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if self.persistence_gate != Some(generation) {
            return Err(CredentialV2Error::Counter);
        }
        self.persistence_gate = None;
        Ok(std::mem::take(&mut self.after_persist))
    }

    /// Seal and durably checkpoint one application object before relay release.
    pub fn prepare_application_object(
        &mut self,
        object: &CredentialV2Object,
        now: u64,
        checkpoint_nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if self.persistence_gate.is_some() {
            return Err(CredentialV2Error::Phase);
        }
        let result = self.prepare_application_object_inner(object, now, checkpoint_nonce);
        if result.is_err() {
            self.terminate();
        }
        result
    }

    fn apply_server(
        &mut self,
        message: ServerMessage,
        now: u64,
        checkpoint_nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        match message {
            ServerMessage::Welcome if self.resume_after_welcome => {
                self.resume_after_welcome = false;
                self.reopen_effects()
            }
            ServerMessage::Welcome if matches!(self.state, AllocatorState::AwaitWelcome) => {
                self.state = AllocatorState::AwaitAllocation;
                Ok(vec![CredentialV2AllocatorEffect::Send(relay_message(
                    ClientMessage::AllocateV2 {
                        mailbox_id: *self.template.mailbox_id(),
                        claim_commitment: self.claim_commitment,
                        ttl_seconds: Some(900),
                    },
                )?)])
            }
            ServerMessage::AllocatedV2 {
                mailbox_id,
                membership_token,
                expires_at,
            } if matches!(self.state, AllocatorState::AwaitAllocation) => self.allocated(
                mailbox_id,
                membership_token,
                expires_at,
                now,
                checkpoint_nonce,
            ),
            ServerMessage::Frame { peer_seq, body } => {
                self.peer_frame(peer_seq, &body, now, checkpoint_nonce)
            }
            ServerMessage::Acknowledged { seq } => {
                self.local_acknowledged(seq, now, checkpoint_nonce)
            }
            ServerMessage::Pong => Ok(Vec::new()),
            ServerMessage::Closed(_) | ServerMessage::Error(_) => {
                self.terminate();
                Ok(vec![CredentialV2AllocatorEffect::Terminal])
            }
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn reopen_effects(&self) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let (carrier, relay, cached) = match &self.state {
            AllocatorState::Bootstrap(bootstrap) => {
                let relay = bootstrap.relay_state();
                let cached = match bootstrap.cached_outbound_frame() {
                    Some(frame) => relay
                        .cached_bootstrap_sequence()?
                        .map(|sequence| (frame, sequence)),
                    None => None,
                };
                (bootstrap.carrier(), relay, cached)
            }
            AllocatorState::Established {
                endpoint, relay, ..
            } => {
                let relay = relay.as_ref();
                let cached = relay
                    .cached_outbound_frame()
                    .map(|frame| {
                        relay
                            .cached_application_sequence()
                            .map(|sequence| (frame, sequence))
                    })
                    .transpose()?;
                (&endpoint.carrier, relay, cached)
            }
            _ => return Err(CredentialV2Error::Phase),
        };
        let mut effects = vec![CredentialV2AllocatorEffect::Send(relay_message(
            ClientMessage::Open {
                mailbox_id: *carrier.mailbox_id(),
                membership_token: *relay.membership_token(),
            },
        )?)];
        if let Some((frame, sequence)) = cached {
            effects.push(CredentialV2AllocatorEffect::Send(relay_message(
                ClientMessage::Put {
                    seq: sequence,
                    body: super::encode_frame(frame)?,
                },
            )?));
        }
        Ok(effects)
    }

    fn allocated(
        &mut self,
        mailbox_id: [u8; 32],
        membership_token: [u8; 32],
        expires_at: u64,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if mailbox_id != *self.template.mailbox_id() || now >= expires_at {
            return Err(CredentialV2Error::Profile);
        }
        let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
            application_context: self.template.application_context().into(),
            relay_origin: self.template.relay_origin().into(),
            mailbox_id,
            carrier_ceremony_id: *self.template.carrier_ceremony_id(),
            carrier_nonce: *self.template.carrier_nonce(),
            claim_commitment: self.claim_commitment,
            relay_expires_at: expires_at,
            expected_allocator_key: self.template.expected_allocator_key().copied(),
        })?;
        let presence = self.presence.take().ok_or(CredentialV2Error::Phase)?;
        self.state = AllocatorState::Bootstrap(Box::new(CredentialV2AllocatorBootstrap::new(
            carrier,
            presence,
            self.profile_digest,
            CredentialV2RelayState::new(membership_token),
            self.mode,
        )?));
        let carrier = self.carrier_bytes()?;
        self.checkpoint_bootstrap(
            now,
            nonce,
            vec![CredentialV2AllocatorEffect::PendingAllocation {
                carrier: carrier.clone(),
            }],
        )
    }

    fn peer_frame(
        &mut self,
        peer_seq: u8,
        body: &[u8],
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let frame = decode_frame(body)?;
        if matches!(self.state, AllocatorState::Established { .. }) {
            return self.peer_application_frame(peer_seq, frame, now, nonce);
        }
        // A lost Ack may cause the relay to redeliver the exact first share.
        // The persistence gate above prevents this path before its durable binding.
        if peer_seq == 0 && self.bootstrap()?.peer_cpace().is_some() {
            let bootstrap = self.bootstrap()?;
            if now >= bootstrap.carrier().relay_expires_at() {
                return Err(CredentialV2Error::Expired);
            }
            if bootstrap.peer_cpace() != Some(&frame) {
                return Err(CredentialV2Error::Profile);
            }
            let mut effects = vec![CredentialV2AllocatorEffect::Send(relay_message(
                ClientMessage::Ack { peer_seq },
            )?)];
            if let Some(sequence) = bootstrap.relay_state().cached_bootstrap_sequence()? {
                let cached = bootstrap
                    .cached_outbound_frame()
                    .ok_or(CredentialV2Error::Phase)?;
                effects.push(CredentialV2AllocatorEffect::Send(relay_message(
                    ClientMessage::Put {
                        seq: sequence,
                        body: super::encode_frame(cached)?,
                    },
                )?));
            }
            return Ok(effects);
        }
        let phase = self.bootstrap()?.phase();
        match phase {
            CredentialV2AllocatorBootstrapPhase::Allocated => {
                let scalar = self.cpace_scalar.take().ok_or(CredentialV2Error::Phase)?;
                let (sequence, outbound) = {
                    let bootstrap = self.bootstrap_mut()?;
                    bootstrap.relay_state_mut().accept_peer_sequence(peer_seq)?;
                    bootstrap.claimant_admitted()?;
                    let outbound = bootstrap.start_cpace(*scalar)?;
                    bootstrap.retain_peer_cpace(&frame)?;
                    let sequence = bootstrap.relay_state_mut().queue_bootstrap_frame()?;
                    (sequence, outbound)
                };
                self.checkpoint_bootstrap(
                    now,
                    nonce,
                    vec![
                        CredentialV2AllocatorEffect::Send(relay_message(ClientMessage::Ack {
                            peer_seq,
                        })?),
                        CredentialV2AllocatorEffect::Send(relay_message(ClientMessage::Put {
                            seq: sequence,
                            body: super::encode_frame(&outbound)?,
                        })?),
                    ],
                )
            }
            CredentialV2AllocatorBootstrapPhase::FinishedSent => {
                let waiting = {
                    let bootstrap = self.bootstrap_mut()?;
                    bootstrap.relay_state_mut().accept_peer_sequence(peer_seq)?;
                    bootstrap.retain_peer_finished(&frame)?;
                    bootstrap.relay_state().awaiting_ack()
                };
                let ack = CredentialV2AllocatorEffect::Send(relay_message(ClientMessage::Ack {
                    peer_seq,
                })?);
                if waiting {
                    self.checkpoint_bootstrap(now, nonce, vec![ack])
                } else {
                    self.establish(now, nonce, Some(ack))
                }
            }
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn local_acknowledged(
        &mut self,
        sequence: u8,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if matches!(self.state, AllocatorState::Established { .. }) {
            return self.application_acknowledged(sequence, now, nonce);
        }
        match self.bootstrap()?.phase() {
            CredentialV2AllocatorBootstrapPhase::ShareSent => {
                let (next_sequence, finished) = {
                    let bootstrap = self.bootstrap_mut()?;
                    bootstrap
                        .relay_state_mut()
                        .acknowledge_bootstrap_frame(sequence)?;
                    let finished = bootstrap.prepare_finished()?;
                    let next_sequence = bootstrap.relay_state_mut().queue_bootstrap_frame()?;
                    (next_sequence, finished)
                };
                self.checkpoint_bootstrap(
                    now,
                    nonce,
                    vec![CredentialV2AllocatorEffect::Send(relay_message(
                        ClientMessage::Put {
                            seq: next_sequence,
                            body: super::encode_frame(&finished)?,
                        },
                    )?)],
                )
            }
            CredentialV2AllocatorBootstrapPhase::FinishedSent => {
                let has_peer = {
                    let bootstrap = self.bootstrap_mut()?;
                    bootstrap
                        .relay_state_mut()
                        .acknowledge_bootstrap_frame(sequence)?;
                    bootstrap.peer_finished().is_some()
                };
                if has_peer {
                    self.establish(now, nonce, None)
                } else {
                    self.checkpoint_bootstrap(now, nonce, Vec::new())
                }
            }
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn establish(
        &mut self,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
        ack: Option<CredentialV2AllocatorEffect>,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let state = std::mem::replace(&mut self.state, AllocatorState::Terminal);
        let AllocatorState::Bootstrap(bootstrap) = state else {
            return Err(CredentialV2Error::Phase);
        };
        let peer_finished = bootstrap
            .peer_finished()
            .cloned()
            .ok_or(CredentialV2Error::Finished)?;
        let carrier = bootstrap.carrier().clone();
        let (generation, prior_nonce) = bootstrap.checkpoint_state();
        let (channel, relay) = bootstrap.confirm(&peer_finished)?;
        if relay.awaiting_ack() {
            return Err(CredentialV2Error::Phase);
        }
        let transcript_hash = channel.transcript_hash();
        let mut endpoint = CredentialV2Endpoint::new(
            Side::Allocator,
            carrier.clone(),
            self.body_verifier.take().ok_or(CredentialV2Error::Phase)?,
        );
        endpoint.checkpoint_generation = generation;
        endpoint.checkpoint_nonce = prior_nonce;
        let checkpoint = endpoint.seal_checkpoint(
            &channel,
            &relay,
            &self.wrapping_key,
            generation.saturating_add(1),
            Some(carrier.relay_expires_at()),
            nonce,
            now,
        )?;
        let next_generation = generation.saturating_add(1);
        let carrier_bytes = encode_carrier(&carrier)?;
        self.state = AllocatorState::Established {
            endpoint: Box::new(endpoint),
            channel: Box::new(channel),
            relay: Box::new(relay),
        };
        let mut after = Vec::new();
        if let Some(ack) = ack {
            after.push(ack);
        }
        after.push(CredentialV2AllocatorEffect::Established { transcript_hash });
        self.gate(next_generation, checkpoint, carrier_bytes, after)
    }

    fn prepare_application_object_inner(
        &mut self,
        object: &CredentialV2Object,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let (sequence, frame) = match &mut self.state {
            AllocatorState::Established {
                endpoint,
                channel,
                relay,
            } => {
                let frame = endpoint.prepare_outbound(object, channel, relay)?;
                let sequence = relay.cached_application_sequence()?;
                (sequence, frame)
            }
            _ => return Err(CredentialV2Error::Phase),
        };
        self.checkpoint_established(
            now,
            nonce,
            vec![CredentialV2AllocatorEffect::Send(relay_message(
                ClientMessage::Put {
                    seq: sequence,
                    body: super::encode_frame(&frame)?,
                },
            )?)],
        )
    }

    fn peer_application_frame(
        &mut self,
        peer_seq: u8,
        frame: super::CredentialV2Frame,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let object = match &mut self.state {
            AllocatorState::Established {
                endpoint,
                channel,
                relay,
            } => {
                relay.accept_peer_sequence(peer_seq)?;
                let plaintext = channel.open(&frame)?;
                let object = decode_object(&plaintext)?;
                endpoint.receive(&object)?;
                object
            }
            _ => return Err(CredentialV2Error::Phase),
        };
        self.checkpoint_established(
            now,
            nonce,
            vec![
                CredentialV2AllocatorEffect::Send(relay_message(ClientMessage::Ack { peer_seq })?),
                CredentialV2AllocatorEffect::ReceivedObject { object },
            ],
        )
    }

    fn application_acknowledged(
        &mut self,
        sequence: u8,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        match &mut self.state {
            AllocatorState::Established { relay, .. } => {
                relay.acknowledge_application_frame(sequence)?;
            }
            _ => return Err(CredentialV2Error::Phase),
        }
        self.checkpoint_established(now, nonce, Vec::new())
    }

    fn checkpoint_established(
        &mut self,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
        after: Vec<CredentialV2AllocatorEffect>,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let wrapping_key = *self.wrapping_key;
        let (generation, checkpoint, carrier) = match &mut self.state {
            AllocatorState::Established {
                endpoint,
                channel,
                relay,
            } => {
                let generation = endpoint.checkpoint_generation.saturating_add(1);
                let expiry = endpoint.carrier.relay_expires_at();
                let checkpoint = endpoint.seal_checkpoint(
                    channel,
                    relay,
                    &wrapping_key,
                    generation,
                    Some(expiry),
                    nonce,
                    now,
                )?;
                let carrier = encode_carrier(&endpoint.carrier)?;
                (generation, checkpoint, carrier)
            }
            _ => return Err(CredentialV2Error::Phase),
        };
        self.gate(generation, checkpoint, carrier, after)
    }

    fn checkpoint_bootstrap(
        &mut self,
        now: u64,
        nonce: CredentialV2CheckpointNonce,
        after: Vec<CredentialV2AllocatorEffect>,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        let wrapping_key = *self.wrapping_key;
        let bootstrap = self.bootstrap_mut()?;
        let generation = bootstrap.checkpoint_state().0.saturating_add(1);
        let checkpoint = bootstrap.seal_checkpoint(&wrapping_key, generation, nonce, now)?;
        let carrier = encode_carrier(bootstrap.carrier())?;
        self.gate(generation, checkpoint, carrier, after)
    }

    fn gate(
        &mut self,
        generation: u64,
        checkpoint: EndpointCheckpointV2,
        carrier: Vec<u8>,
        after: Vec<CredentialV2AllocatorEffect>,
    ) -> Result<Vec<CredentialV2AllocatorEffect>, CredentialV2Error> {
        if self.persistence_gate.replace(generation).is_some() || !self.after_persist.is_empty() {
            return Err(CredentialV2Error::Phase);
        }
        self.after_persist = after;
        Ok(vec![CredentialV2AllocatorEffect::Checkpoint {
            generation,
            checkpoint,
            carrier,
        }])
    }

    fn terminate(&mut self) {
        self.state = AllocatorState::Terminal;
        self.presence = None;
        self.cpace_scalar = None;
        self.wrapping_key.zeroize();
        self.after_persist.clear();
    }

    fn carrier_bytes(&self) -> Result<Vec<u8>, CredentialV2Error> {
        encode_carrier(self.bootstrap()?.carrier())
    }

    fn bootstrap(&self) -> Result<&CredentialV2AllocatorBootstrap, CredentialV2Error> {
        match &self.state {
            AllocatorState::Bootstrap(value) => Ok(value),
            _ => Err(CredentialV2Error::Phase),
        }
    }

    fn bootstrap_mut(&mut self) -> Result<&mut CredentialV2AllocatorBootstrap, CredentialV2Error> {
        match &mut self.state {
            AllocatorState::Bootstrap(value) => Ok(value),
            _ => Err(CredentialV2Error::Phase),
        }
    }
}

fn relay_message(message: ClientMessage) -> Result<Vec<u8>, CredentialV2Error> {
    encode_client_message(&message).map_err(|_| CredentialV2Error::Schema)
}

#[cfg(test)]
mod tests;
