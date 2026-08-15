//! Reference application-unaware relay service.
//!
//! The service composes the pure mailbox transition, shared limiter, and
//! closed observability dimensions. Time, peer addresses, transport connection
//! identifiers, and randomness are explicit shell inputs.

use crate::{
    limiter::{LimitDecision, Limiter, LimiterConfig, LimiterError, Operation},
    mailbox::{
        reap, transition, AllocationInput, Mailbox, MailboxCommand, MailboxEffect, MailboxError,
        MailboxTransition, Membership, MembershipHash,
    },
    observability::{
        CapacityCaps, RelayGauges, RelayLogEvent, RelayMetrics, RelayObservability, RelayOutcome,
    },
    wire::{ClientMessage, CloseReason, Locator, ServerMessage},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

/// Process-local identifier for one relay connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

/// Shell-supplied random values for commands that allocate identifiers or
/// membership tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayRandomness {
    /// Candidate random mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Candidate random membership token.
    pub membership_token: [u8; 32],
    /// Candidate numeric nameplate.
    pub nameplate: u32,
}

/// Bounded reference-relay configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayConfig {
    /// Private operator key used only for peer-address limiter HMACs.
    pub operator_key: [u8; 32],
    /// Shared limiter configuration.
    pub limiter: LimiterConfig,
    /// Hard observable resource caps.
    pub capacity: CapacityCaps,
    /// Whether new invitation allocation is enabled.
    pub allocation_enabled: bool,
}

/// One response routed to a live connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedMessage {
    /// Destination connection.
    pub connection: ConnectionId,
    /// Fully recognised response.
    pub message: ServerMessage,
}

/// Reference service error that cannot be represented as a normal wire reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// Relay configuration is invalid.
    InvalidConfiguration,
    /// Time or limiter state failed.
    Limiter,
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RelayError {}

impl From<LimiterError> for RelayError {
    fn from(_: LimiterError) -> Self {
        Self::Limiter
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionMembership {
    mailbox_id: [u8; 32],
    membership: Membership,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConnectionState {
    bound: bool,
    membership: Option<SessionMembership>,
}

/// Application-unaware in-memory relay service.
pub struct RelayService {
    config: RelayConfig,
    limiter: Limiter,
    observability: RelayObservability,
    mailboxes: BTreeMap<[u8; 32], Mailbox>,
    nameplates: BTreeMap<u32, [u8; 32]>,
    connections: BTreeMap<ConnectionId, ConnectionState>,
    routes: BTreeMap<([u8; 32], u8), ConnectionId>,
    last_log: Option<RelayLogEvent>,
}

impl fmt::Debug for RelayService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayService")
            .field("allocation_enabled", &self.config.allocation_enabled)
            .field("mailbox_count", &self.mailboxes.len())
            .field("connection_count", &self.connections.len())
            .field("metrics", &self.observability.metrics())
            .field("operator_key", &"REDACTED")
            .finish()
    }
}

impl RelayService {
    /// Construct a bounded service.
    pub fn new(config: RelayConfig) -> Result<Self, RelayError> {
        if config.capacity.open_mailboxes == 0
            || config.capacity.queue_bytes == 0
            || config.capacity.limiter_entries == 0
            || config.capacity.limiter_entries != config.limiter.entry_cap() as u64
        {
            return Err(RelayError::InvalidConfiguration);
        }
        let limiter = Limiter::new(config.operator_key, config.limiter.clone())?;
        let observability = RelayObservability::new(config.capacity);
        let mut service = Self {
            config,
            limiter,
            observability,
            mailboxes: BTreeMap::new(),
            nameplates: BTreeMap::new(),
            connections: BTreeMap::new(),
            routes: BTreeMap::new(),
            last_log: None,
        };
        service.refresh_gauges();
        Ok(service)
    }

    /// Apply one fully recognised client command.
    pub fn handle(
        &mut self,
        connection: ConnectionId,
        canonical_peer_address: &[u8],
        now: u64,
        randomness: RelayRandomness,
        message: ClientMessage,
    ) -> Result<Vec<RoutedMessage>, RelayError> {
        let operation = operation(&message);
        match self.limiter.check(operation, canonical_peer_address, now)? {
            LimitDecision::Allowed { .. } => {}
            LimitDecision::Cooldown { .. } => {
                return Ok(self.finish(
                    operation,
                    RelayOutcome::RateLimited,
                    vec![route(connection, ServerMessage::Error(429))],
                ));
            }
            LimitDecision::AtCapacity => {
                return Ok(self.finish(
                    operation,
                    RelayOutcome::Unavailable,
                    vec![route(connection, ServerMessage::Error(503))],
                ));
            }
        }

        let bound = self
            .connections
            .get(&connection)
            .is_some_and(|state| state.bound);
        let messages = if matches!(message, ClientMessage::Bind) {
            self.connections.entry(connection).or_default().bound = true;
            vec![route(connection, ServerMessage::Welcome)]
        } else if !bound {
            vec![route(connection, ServerMessage::Error(400))]
        } else {
            match message {
                ClientMessage::Bind => unreachable!("handled above"),
                ClientMessage::Allocate {
                    locator_mode,
                    ttl_seconds,
                } => self.allocate(connection, now, randomness, locator_mode, ttl_seconds),
                ClientMessage::Claim(locator) => {
                    self.claim(connection, now, randomness.membership_token, &locator)
                }
                ClientMessage::Open {
                    mailbox_id,
                    membership_token,
                } => self.open(connection, now, mailbox_id, membership_token),
                ClientMessage::Put { seq, body } => {
                    self.member_command(connection, now, MailboxCommandKind::Put { seq, body })
                }
                ClientMessage::Ack { peer_seq } => {
                    self.member_command(connection, now, MailboxCommandKind::Ack { peer_seq })
                }
                ClientMessage::Close => {
                    self.member_command(connection, now, MailboxCommandKind::Close)
                }
                ClientMessage::Ping => vec![route(connection, ServerMessage::Pong)],
            }
        };
        let outcome = actor_outcome(connection, &messages);
        Ok(self.finish(operation, outcome, messages))
    }

    /// Remove one transport connection without closing its mailbox.
    pub fn disconnect(&mut self, connection: ConnectionId) {
        if let Some(state) = self.connections.remove(&connection) {
            if let Some(member) = state.membership {
                if self.routes.get(&route_key(member)) == Some(&connection) {
                    self.routes.remove(&route_key(member));
                }
            }
        }
    }

    /// Reap mailboxes and limiter entries using explicit time.
    pub fn sweep(&mut self, now: u64) -> Result<Vec<RoutedMessage>, RelayError> {
        self.limiter.sweep(now)?;
        let ids: Vec<_> = self.mailboxes.keys().copied().collect();
        let mut messages = Vec::new();
        for mailbox_id in ids {
            let Some(state) = self.mailboxes.get(&mailbox_id).cloned() else {
                continue;
            };
            let transition = reap(&state, now).map_err(|_| RelayError::InvalidConfiguration)?;
            if transition.state.is_none() {
                messages.extend(self.terminal_routes(mailbox_id, CloseReason::Expired));
                self.remove_mailbox(mailbox_id, &state);
            }
        }
        self.refresh_gauges();
        Ok(messages)
    }

    /// Return the last closed-dimension log event, with no dynamic values.
    #[must_use]
    pub const fn last_log_event(&self) -> Option<RelayLogEvent> {
        self.last_log
    }

    /// Return the privacy-safe metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> RelayMetrics {
        self.observability.metrics()
    }

    /// Return the number of retained mailboxes for conformance inspection.
    #[must_use]
    pub fn mailbox_count(&self) -> usize {
        self.mailboxes.len()
    }

    fn allocate(
        &mut self,
        connection: ConnectionId,
        now: u64,
        randomness: RelayRandomness,
        locator_mode: u8,
        ttl_seconds: Option<u16>,
    ) -> Vec<RoutedMessage> {
        if !self.config.allocation_enabled {
            return vec![route(connection, ServerMessage::Error(503))];
        }
        if self
            .connections
            .get(&connection)
            .and_then(|state| state.membership)
            .is_some()
        {
            return vec![route(connection, ServerMessage::Error(409))];
        }
        if self.mailboxes.len() as u64 >= self.config.capacity.open_mailboxes
            || self.mailboxes.contains_key(&randomness.mailbox_id)
            || self.token_hash_exists(token_hash(&randomness.membership_token))
        {
            return vec![route(connection, ServerMessage::Error(503))];
        }
        let nameplate = match locator_mode {
            0 => None,
            1 if randomness.nameplate <= 999_999_999
                && !self.nameplates.contains_key(&randomness.nameplate) =>
            {
                Some(randomness.nameplate)
            }
            1 => return vec![route(connection, ServerMessage::Error(503))],
            _ => return vec![route(connection, ServerMessage::Error(400))],
        };
        let mailbox = match Mailbox::allocate(AllocationInput {
            mailbox_id: randomness.mailbox_id,
            nameplate,
            allocator_hash: token_hash(&randomness.membership_token),
            now,
            ttl_seconds,
        }) {
            Ok(value) => value,
            Err(error) => return vec![route(connection, mailbox_error(&error))],
        };
        let expires_at = mailbox.expires_at();
        self.mailboxes.insert(randomness.mailbox_id, mailbox);
        if let Some(nameplate) = nameplate {
            self.nameplates.insert(nameplate, randomness.mailbox_id);
        }
        self.attach(
            connection,
            SessionMembership {
                mailbox_id: randomness.mailbox_id,
                membership: Membership::Allocator,
            },
        );
        vec![route(
            connection,
            ServerMessage::Allocated {
                mailbox_id: randomness.mailbox_id,
                membership_token: randomness.membership_token,
                nameplate,
                expires_at,
            },
        )]
    }

    fn claim(
        &mut self,
        connection: ConnectionId,
        now: u64,
        membership_token: [u8; 32],
        locator: &Locator,
    ) -> Vec<RoutedMessage> {
        if self
            .connections
            .get(&connection)
            .and_then(|state| state.membership)
            .is_some()
        {
            return vec![route(connection, ServerMessage::Error(409))];
        }
        let Some(mailbox_id) = self.resolve(locator) else {
            return vec![route(connection, ServerMessage::Error(404))];
        };
        let claimant_hash = token_hash(&membership_token);
        if self.token_hash_exists(claimant_hash) {
            return vec![route(connection, ServerMessage::Error(409))];
        }
        let Some(state) = self.mailboxes.get(&mailbox_id).cloned() else {
            return vec![route(connection, ServerMessage::Error(404))];
        };
        let transition = match transition(&state, now, MailboxCommand::Claim { claimant_hash }) {
            Ok(value) => value,
            Err(error) => return vec![route(connection, mailbox_error(&error))],
        };
        let claimed = transition.effects.iter().find_map(|effect| match effect {
            MailboxEffect::Claimed { expires_at, .. } => Some(*expires_at),
            _ => None,
        });
        let terminal = transition.effects.iter().find_map(|effect| match effect {
            MailboxEffect::Terminal(reason) => Some(*reason),
            _ => None,
        });
        self.commit(mailbox_id, transition);
        if let Some(expires_at) = claimed {
            self.attach(
                connection,
                SessionMembership {
                    mailbox_id,
                    membership: Membership::Claimant,
                },
            );
            vec![route(
                connection,
                ServerMessage::Claimed {
                    mailbox_id,
                    membership_token,
                    expires_at,
                },
            )]
        } else if let Some(reason) = terminal {
            let mut messages = self.terminal_routes(mailbox_id, reason);
            messages.push(route(connection, ServerMessage::Closed(reason)));
            deduplicate_routes(messages)
        } else {
            vec![route(connection, ServerMessage::Error(503))]
        }
    }

    fn open(
        &mut self,
        connection: ConnectionId,
        now: u64,
        mailbox_id: [u8; 32],
        membership_token: [u8; 32],
    ) -> Vec<RoutedMessage> {
        let Some(state) = self.mailboxes.get(&mailbox_id).cloned() else {
            return vec![route(connection, ServerMessage::Error(404))];
        };
        let transition = match transition(
            &state,
            now,
            MailboxCommand::Open {
                membership_hash: token_hash(&membership_token),
            },
        ) {
            Ok(value) => value,
            Err(error) => return vec![route(connection, mailbox_error(&error))],
        };
        let membership = transition.effects.iter().find_map(|effect| match effect {
            MailboxEffect::Opened { membership, .. } => Some(*membership),
            _ => None,
        });
        let terminal = transition.effects.iter().find_map(|effect| match effect {
            MailboxEffect::Terminal(reason) => Some(*reason),
            _ => None,
        });
        let deliveries: Vec<_> = transition
            .effects
            .iter()
            .filter_map(|effect| match effect {
                MailboxEffect::Deliver { peer_seq, body, .. } => Some(route(
                    connection,
                    ServerMessage::Frame {
                        peer_seq: *peer_seq,
                        body: body.clone(),
                    },
                )),
                _ => None,
            })
            .collect();
        self.commit(mailbox_id, transition);
        if let Some(membership) = membership {
            self.attach(
                connection,
                SessionMembership {
                    mailbox_id,
                    membership,
                },
            );
            deliveries
        } else if let Some(reason) = terminal {
            let mut messages = self.terminal_routes(mailbox_id, reason);
            messages.push(route(connection, ServerMessage::Closed(reason)));
            deduplicate_routes(messages)
        } else {
            vec![route(connection, ServerMessage::Error(503))]
        }
    }

    fn member_command(
        &mut self,
        connection: ConnectionId,
        now: u64,
        command: MailboxCommandKind,
    ) -> Vec<RoutedMessage> {
        let Some(session) = self
            .connections
            .get(&connection)
            .and_then(|state| state.membership)
        else {
            return vec![route(connection, ServerMessage::Error(404))];
        };
        let Some(state) = self.mailboxes.get(&session.mailbox_id).cloned() else {
            return vec![route(connection, ServerMessage::Error(404))];
        };
        let mailbox_command = match &command {
            MailboxCommandKind::Put { seq, body } => MailboxCommand::Put {
                sender: session.membership,
                seq: *seq,
                body: body.clone(),
            },
            MailboxCommandKind::Ack { peer_seq } => MailboxCommand::Ack {
                sender: session.membership,
                peer_seq: *peer_seq,
            },
            MailboxCommandKind::Close => MailboxCommand::Close {
                sender: session.membership,
            },
        };
        let transition = match transition(&state, now, mailbox_command) {
            Ok(value) => value,
            Err(error) => return vec![route(connection, mailbox_error(&error))],
        };
        if projected_queue_bytes(&self.mailboxes, session.mailbox_id, &transition)
            > self.config.capacity.queue_bytes
        {
            return vec![route(connection, ServerMessage::Error(503))];
        }
        let mut messages = Vec::new();
        match &command {
            MailboxCommandKind::Put { seq, .. } => {
                if transition.effects.iter().any(|effect| {
                    matches!(effect, MailboxEffect::Stored { seq: stored, .. } if stored == seq)
                }) {
                    messages.push(route(
                        connection,
                        ServerMessage::Acknowledged { seq: *seq },
                    ));
                }
            }
            MailboxCommandKind::Ack { peer_seq } => messages.push(route(
                connection,
                ServerMessage::Acknowledged { seq: *peer_seq },
            )),
            MailboxCommandKind::Close => {}
        }
        for effect in &transition.effects {
            match effect {
                MailboxEffect::Deliver {
                    recipient,
                    peer_seq,
                    body,
                } => {
                    if let Some(recipient) = self.routes.get(&route_key(SessionMembership {
                        mailbox_id: session.mailbox_id,
                        membership: *recipient,
                    })) {
                        messages.push(route(
                            *recipient,
                            ServerMessage::Frame {
                                peer_seq: *peer_seq,
                                body: body.clone(),
                            },
                        ));
                    }
                }
                MailboxEffect::Terminal(reason) => {
                    messages.extend(self.terminal_routes(session.mailbox_id, *reason));
                }
                _ => {}
            }
        }
        self.commit(session.mailbox_id, transition);
        deduplicate_routes(messages)
    }

    fn attach(&mut self, connection: ConnectionId, membership: SessionMembership) {
        if let Some(previous) = self
            .connections
            .get(&connection)
            .and_then(|state| state.membership)
        {
            if self.routes.get(&route_key(previous)) == Some(&connection) {
                self.routes.remove(&route_key(previous));
            }
        }
        if let Some(old_connection) = self.routes.insert(route_key(membership), connection) {
            if old_connection != connection {
                if let Some(old) = self.connections.get_mut(&old_connection) {
                    old.membership = None;
                }
            }
        }
        self.connections.entry(connection).or_default().membership = Some(membership);
    }

    fn resolve(&self, locator: &Locator) -> Option<[u8; 32]> {
        match locator {
            Locator::Direct(mailbox_id) if self.mailboxes.contains_key(mailbox_id) => {
                Some(*mailbox_id)
            }
            Locator::Direct(_) => None,
            Locator::Nameplate(nameplate) => self.nameplates.get(nameplate).copied(),
        }
    }

    fn token_hash_exists(&self, hash: MembershipHash) -> bool {
        self.mailboxes.values().any(|mailbox| {
            mailbox
                .snapshot()
                .membership_hashes
                .into_iter()
                .any(|existing| existing == hash)
        })
    }

    fn commit(&mut self, mailbox_id: [u8; 32], transition: MailboxTransition) {
        if let Some(state) = transition.state {
            self.mailboxes.insert(mailbox_id, state);
        } else if let Some(previous) = self.mailboxes.remove(&mailbox_id) {
            self.remove_mailbox_indexes(mailbox_id, &previous);
        }
    }

    fn terminal_routes(&self, mailbox_id: [u8; 32], reason: CloseReason) -> Vec<RoutedMessage> {
        [Membership::Allocator, Membership::Claimant]
            .into_iter()
            .filter_map(|membership| {
                self.routes.get(&route_key(SessionMembership {
                    mailbox_id,
                    membership,
                }))
            })
            .map(|connection| route(*connection, ServerMessage::Closed(reason)))
            .collect()
    }

    fn remove_mailbox(&mut self, mailbox_id: [u8; 32], state: &Mailbox) {
        self.mailboxes.remove(&mailbox_id);
        self.remove_mailbox_indexes(mailbox_id, state);
    }

    fn remove_mailbox_indexes(&mut self, mailbox_id: [u8; 32], state: &Mailbox) {
        if let Some(nameplate) = state.snapshot().nameplate {
            self.nameplates.remove(&nameplate);
        }
        for membership in [Membership::Allocator, Membership::Claimant] {
            if let Some(connection) = self.routes.remove(&route_key(SessionMembership {
                mailbox_id,
                membership,
            })) {
                if let Some(state) = self.connections.get_mut(&connection) {
                    state.membership = None;
                }
            }
        }
    }

    fn finish(
        &mut self,
        operation: Operation,
        outcome: RelayOutcome,
        messages: Vec<RoutedMessage>,
    ) -> Vec<RoutedMessage> {
        self.last_log = Some(self.observability.record(operation, outcome));
        self.refresh_gauges();
        messages
    }

    fn refresh_gauges(&mut self) {
        self.observability.set_gauges(RelayGauges {
            open_mailboxes: self.mailboxes.len() as u64,
            queue_bytes: queue_bytes(&self.mailboxes),
            limiter_entries: self.limiter.snapshot().entry_count as u64,
        });
    }
}

enum MailboxCommandKind {
    Put { seq: u8, body: Vec<u8> },
    Ack { peer_seq: u8 },
    Close,
}

fn operation(message: &ClientMessage) -> Operation {
    match message {
        ClientMessage::Bind => Operation::Bind,
        ClientMessage::Allocate { .. } => Operation::Allocate,
        ClientMessage::Claim(_) => Operation::Claim,
        ClientMessage::Open { .. } => Operation::Open,
        ClientMessage::Put { .. } => Operation::Put,
        ClientMessage::Ack { .. } => Operation::Ack,
        ClientMessage::Close => Operation::Close,
        ClientMessage::Ping => Operation::Ping,
    }
}

fn token_hash(token: &[u8; 32]) -> MembershipHash {
    MembershipHash::new(Sha256::digest(token).into())
}

fn route_key(membership: SessionMembership) -> ([u8; 32], u8) {
    (
        membership.mailbox_id,
        match membership.membership {
            Membership::Allocator => 0,
            Membership::Claimant => 1,
        },
    )
}

fn route(connection: ConnectionId, message: ServerMessage) -> RoutedMessage {
    RoutedMessage {
        connection,
        message,
    }
}

fn mailbox_error(error: &MailboxError) -> ServerMessage {
    match error {
        MailboxError::Closed(reason) => ServerMessage::Closed(*reason),
        _ => ServerMessage::Error(error.wire_code()),
    }
}

fn actor_outcome(connection: ConnectionId, messages: &[RoutedMessage]) -> RelayOutcome {
    let actor = messages
        .iter()
        .find(|message| message.connection == connection);
    match actor.map(|message| &message.message) {
        Some(ServerMessage::Error(404)) => RelayOutcome::NotFound,
        Some(ServerMessage::Error(409)) => RelayOutcome::Conflict,
        Some(ServerMessage::Error(413)) => RelayOutcome::TooLarge,
        Some(ServerMessage::Error(429)) => RelayOutcome::RateLimited,
        Some(ServerMessage::Error(503)) => RelayOutcome::Unavailable,
        Some(ServerMessage::Error(_)) => RelayOutcome::Invalid,
        Some(ServerMessage::Closed(CloseReason::Closed)) => RelayOutcome::Closed,
        Some(ServerMessage::Closed(CloseReason::Crowded)) => RelayOutcome::Crowded,
        Some(ServerMessage::Closed(CloseReason::Expired)) => RelayOutcome::Expired,
        Some(ServerMessage::Closed(CloseReason::Conflict)) => RelayOutcome::Conflict,
        Some(_) | None => RelayOutcome::Success,
    }
}

fn queue_bytes(mailboxes: &BTreeMap<[u8; 32], Mailbox>) -> u64 {
    mailboxes
        .values()
        .flat_map(|mailbox| mailbox.snapshot().sequences)
        .filter_map(|sequence| sequence.body.map(|body| body.len() as u64))
        .sum()
}

fn projected_queue_bytes(
    mailboxes: &BTreeMap<[u8; 32], Mailbox>,
    replaced: [u8; 32],
    transition: &MailboxTransition,
) -> u64 {
    let existing: u64 = mailboxes
        .iter()
        .filter(|(mailbox_id, _)| **mailbox_id != replaced)
        .map(|(_, mailbox)| {
            mailbox
                .snapshot()
                .sequences
                .into_iter()
                .filter_map(|sequence| sequence.body.map(|body| body.len() as u64))
                .sum::<u64>()
        })
        .sum();
    let replacement = transition.state.as_ref().map_or(0, |mailbox| {
        mailbox
            .snapshot()
            .sequences
            .into_iter()
            .filter_map(|sequence| sequence.body.map(|body| body.len() as u64))
            .sum()
    });
    existing.saturating_add(replacement)
}

fn deduplicate_routes(messages: Vec<RoutedMessage>) -> Vec<RoutedMessage> {
    let mut result = Vec::new();
    for message in messages {
        if !result.contains(&message) {
            result.push(message);
        }
    }
    result
}
