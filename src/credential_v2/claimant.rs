use super::{
    decode_frame, decode_object, encode_frame, CredentialV2Advance, CredentialV2BodyVerifier,
    CredentialV2Carrier, CredentialV2Context, CredentialV2Endpoint, CredentialV2Error,
    CredentialV2Frame, CredentialV2Kind, CredentialV2Phase, CredentialV2Presence,
    CredentialV2PresenceCode, CredentialV2RelayState, PendingCredentialV2Channel,
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

impl fmt::Debug for CredentialV2ClaimantEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(bytes) => formatter.debug_tuple("Send").field(&bytes.len()).finish(),
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
    authenticated_offer_body: Option<Vec<u8>>,
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
            authenticated_offer_body: None,
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
        self.authenticated_offer_body.as_deref()
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
        if self.phase != ClaimantPhase::Established
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
                self.authenticated_offer_body = Some(object.body().to_vec());
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
        self.authenticated_offer_body = None;
    }
}

fn relay_message(message: ClientMessage) -> Result<Vec<u8>, CredentialV2Error> {
    encode_client_message(&message).map_err(|_| CredentialV2Error::Schema)
}
