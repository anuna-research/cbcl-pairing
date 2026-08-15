//! Pure two-membership mailbox state and transition effects.

use crate::wire::CloseReason;
use sha2::{Digest, Sha256};

/// Default mailbox lifetime in seconds.
pub const DEFAULT_TTL_SECONDS: u16 = 600;
/// Minimum accepted mailbox lifetime in seconds.
pub const MIN_TTL_SECONDS: u16 = 60;
/// Maximum accepted mailbox lifetime in seconds.
pub const MAX_TTL_SECONDS: u16 = 600;
/// Maximum frames accepted from one membership.
pub const MAX_FRAMES_PER_MEMBERSHIP: usize = 16;
/// Maximum opaque frame body length.
pub const MAX_FRAME_BODY_BYTES: usize = 69_632;

/// Hash of a relay-issued membership token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MembershipHash([u8; 32]);

impl MembershipHash {
    /// Wrap a token hash produced by the effectful relay shell.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the exact hash octets.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One of the mailbox's two fixed memberships.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Membership {
    /// Initial allocator membership A.
    Allocator,
    /// First claimant membership B.
    Claimant,
}

impl Membership {
    fn peer(self) -> Self {
        match self {
            Self::Allocator => Self::Claimant,
            Self::Claimant => Self::Allocator,
        }
    }
}

/// Inputs whose randomness and time are supplied by the effectful shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationInput {
    /// Random direct mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Optional relay-reserved nameplate.
    pub nameplate: Option<u32>,
    /// Hash of the allocator's random membership token.
    pub allocator_hash: MembershipHash,
    /// Explicit current Unix time in seconds.
    pub now: u64,
    /// Requested lifetime, or the protocol default when absent.
    pub ttl_seconds: Option<u16>,
}

/// A recognised operation against one mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxCommand {
    /// Install the first claimant or crowd an already-paired mailbox.
    Claim {
        /// Hash of the new relay-generated membership token.
        claimant_hash: MembershipHash,
    },
    /// Authenticate and resume one existing membership.
    Open {
        /// Hash of the presented membership token.
        membership_hash: MembershipHash,
    },
    /// Store one membership-local opaque frame.
    Put {
        /// Authenticated sending membership.
        sender: Membership,
        /// Contiguous membership-local sequence.
        seq: u8,
        /// Opaque recognised body.
        body: Vec<u8>,
    },
    /// Acknowledge one frame sent by the peer.
    Ack {
        /// Authenticated acknowledging membership.
        sender: Membership,
        /// Exact peer sequence being acknowledged.
        peer_seq: u8,
    },
    /// Close the mailbox explicitly.
    Close {
        /// Authenticated closing membership.
        sender: Membership,
    },
}

/// Pure effects for the relay shell to route or persist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxEffect {
    /// The first claimant membership was installed.
    Claimed {
        /// Fixed claimant membership.
        membership: Membership,
        /// Original absolute expiry.
        expires_at: u64,
    },
    /// A membership resumed successfully.
    Opened {
        /// Authenticated membership.
        membership: Membership,
        /// Original absolute expiry.
        expires_at: u64,
    },
    /// A new frame or exact retry was accepted for the sender.
    Stored {
        /// Sending membership.
        sender: Membership,
        /// Accepted sequence.
        seq: u8,
        /// Whether this was an exact retry rather than new storage.
        replay: bool,
    },
    /// Offer one exact queued body to its peer.
    Deliver {
        /// Peer receiving the frame.
        recipient: Membership,
        /// Sending peer's sequence.
        peer_seq: u8,
        /// Exact opaque body.
        body: Vec<u8>,
    },
    /// One acknowledged or terminal body was deleted.
    BodyDeleted {
        /// Membership that originally sent the body.
        owner: Membership,
        /// Owner-local sequence.
        seq: u8,
    },
    /// The mailbox entered or reached a terminal condition.
    Terminal(CloseReason),
}

/// Mailbox status retained only until the original expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxStatus {
    /// Allocator exists and no claimant has joined.
    Waiting,
    /// Both memberships exist.
    Paired,
    /// No more live operations are accepted.
    Terminal(CloseReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FrameRecord {
    seq: u8,
    digest: [u8; 32],
    body_len: usize,
    body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemberState {
    hash: MembershipHash,
    next_seq: u8,
    frames: Vec<FrameRecord>,
}

/// Pure state for one allocated mailbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mailbox {
    mailbox_id: [u8; 32],
    nameplate: Option<u32>,
    expires_at: u64,
    status: MailboxStatus,
    allocator: MemberState,
    claimant: Option<MemberState>,
}

/// One sequence's privacy-bounded inspectable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceSnapshot {
    /// Membership that owns the sequence.
    pub owner: Membership,
    /// Owner-local sequence.
    pub seq: u8,
    /// SHA-256 of the opaque body, retained for immutable retries.
    pub body_digest: [u8; 32],
    /// Original body length.
    pub body_len: usize,
    /// Opaque queued body, absent immediately after ACK or terminal closure.
    pub body: Option<Vec<u8>>,
}

/// Complete inspectable relay-domain state, with no application semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxSnapshot {
    /// Direct mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Optional reserved nameplate alias.
    pub nameplate: Option<u32>,
    /// Original absolute expiry.
    pub expires_at: u64,
    /// Waiting, paired, or terminal state.
    pub status: MailboxStatus,
    /// Allocator hash followed by the optional claimant hash.
    pub membership_hashes: Vec<MembershipHash>,
    /// Per-membership sequence metadata and optional opaque bodies.
    pub sequences: Vec<SequenceSnapshot>,
}

/// New pure state plus effects produced by one transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxTransition {
    /// Updated mailbox, or `None` once original expiry reaps all metadata.
    pub state: Option<Mailbox>,
    /// Ordered effects for the effectful shell.
    pub effects: Vec<MailboxEffect>,
}

/// Closed error set for mailbox-domain validation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxError {
    /// Behavioural stub used only for the detailed Red Gate.
    NotImplemented,
    /// Requested lifetime falls outside 60 through 600 seconds.
    LifetimeOutOfRange,
    /// Absolute expiry cannot be represented.
    ExpiryOverflow,
    /// Nameplate exceeds the protocol's nine-digit ceiling.
    NameplateOutOfRange,
    /// Presented membership is absent or invalid.
    NotMember,
    /// The command addressed a terminal mailbox.
    Closed(CloseReason),
    /// A sequence skipped the next required value.
    SequenceGap {
        /// Required next sequence.
        expected: u8,
        /// Submitted sequence.
        got: u8,
    },
    /// The per-membership frame ceiling was reached.
    FrameLimit,
    /// An opaque body falls outside the wire bound.
    BodySize,
    /// Acknowledgement references a sequence that does not exist.
    UnknownSequence,
    /// A new claimant hash collides with an existing membership.
    MembershipCollision,
}

impl MailboxError {
    /// Return the matching closed-enumeration wire error code.
    #[must_use]
    pub const fn wire_code(&self) -> u16 {
        match self {
            Self::LifetimeOutOfRange | Self::NameplateOutOfRange => 400,
            Self::NotMember => 404,
            Self::Closed(_) => 410,
            Self::BodySize => 413,
            Self::NotImplemented | Self::ExpiryOverflow => 503,
            Self::SequenceGap { .. }
            | Self::FrameLimit
            | Self::UnknownSequence
            | Self::MembershipCollision => 409,
        }
    }
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MailboxError {}

impl Mailbox {
    /// Allocate pure state using shell-supplied randomness and time.
    pub fn allocate(input: AllocationInput) -> Result<Self, MailboxError> {
        let ttl_seconds = input.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(MailboxError::LifetimeOutOfRange);
        }
        if input
            .nameplate
            .is_some_and(|nameplate| nameplate > 999_999_999)
        {
            return Err(MailboxError::NameplateOutOfRange);
        }
        let expires_at = input
            .now
            .checked_add(u64::from(ttl_seconds))
            .ok_or(MailboxError::ExpiryOverflow)?;
        Ok(Self {
            mailbox_id: input.mailbox_id,
            nameplate: input.nameplate,
            expires_at,
            status: MailboxStatus::Waiting,
            allocator: MemberState {
                hash: input.allocator_hash,
                next_seq: 0,
                frames: Vec::new(),
            },
            claimant: None,
        })
    }

    /// Return the original absolute expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Return the current mailbox status.
    #[must_use]
    pub const fn status(&self) -> MailboxStatus {
        self.status
    }

    /// Return a privacy-bounded snapshot for persistence and conformance tests.
    #[must_use]
    pub fn snapshot(&self) -> MailboxSnapshot {
        let mut membership_hashes = vec![self.allocator.hash];
        if let Some(claimant) = &self.claimant {
            membership_hashes.push(claimant.hash);
        }
        let mut sequences = Vec::new();
        for (owner, member) in [
            (Membership::Allocator, Some(&self.allocator)),
            (Membership::Claimant, self.claimant.as_ref()),
        ] {
            if let Some(member) = member {
                sequences.extend(member.frames.iter().map(|frame| SequenceSnapshot {
                    owner,
                    seq: frame.seq,
                    body_digest: frame.digest,
                    body_len: frame.body_len,
                    body: frame.body.clone(),
                }));
            }
        }
        MailboxSnapshot {
            mailbox_id: self.mailbox_id,
            nameplate: self.nameplate,
            expires_at: self.expires_at,
            status: self.status,
            membership_hashes,
            sequences,
        }
    }

    fn member(&self, membership: Membership) -> Option<&MemberState> {
        match membership {
            Membership::Allocator => Some(&self.allocator),
            Membership::Claimant => self.claimant.as_ref(),
        }
    }

    fn member_mut(&mut self, membership: Membership) -> Option<&mut MemberState> {
        match membership {
            Membership::Allocator => Some(&mut self.allocator),
            Membership::Claimant => self.claimant.as_mut(),
        }
    }

    fn membership_for_hash(&self, hash: MembershipHash) -> Option<Membership> {
        if self.allocator.hash == hash {
            Some(Membership::Allocator)
        } else if self
            .claimant
            .as_ref()
            .is_some_and(|claimant| claimant.hash == hash)
        {
            Some(Membership::Claimant)
        } else {
            None
        }
    }

    fn delete_bodies(&mut self, effects: &mut Vec<MailboxEffect>) {
        for (owner, member) in [
            (Membership::Allocator, Some(&mut self.allocator)),
            (Membership::Claimant, self.claimant.as_mut()),
        ] {
            if let Some(member) = member {
                for frame in &mut member.frames {
                    if frame.body.take().is_some() {
                        effects.push(MailboxEffect::BodyDeleted {
                            owner,
                            seq: frame.seq,
                        });
                    }
                }
            }
        }
    }

    fn terminate(mut self, reason: CloseReason) -> MailboxTransition {
        let mut effects = Vec::new();
        self.delete_bodies(&mut effects);
        self.status = MailboxStatus::Terminal(reason);
        effects.push(MailboxEffect::Terminal(reason));
        MailboxTransition {
            state: Some(self),
            effects,
        }
    }
}

/// Apply one recognised command to immutable mailbox input.
pub fn transition(
    state: &Mailbox,
    now: u64,
    command: MailboxCommand,
) -> Result<MailboxTransition, MailboxError> {
    if now >= state.expires_at {
        return reap(state, now);
    }
    if let MailboxStatus::Terminal(reason) = state.status {
        return Err(MailboxError::Closed(reason));
    }

    let mut next = state.clone();
    match command {
        MailboxCommand::Claim { claimant_hash } => {
            if claimant_hash == next.allocator.hash {
                return Err(MailboxError::MembershipCollision);
            }
            match &next.claimant {
                None => {
                    next.claimant = Some(MemberState {
                        hash: claimant_hash,
                        next_seq: 0,
                        frames: Vec::new(),
                    });
                    next.status = MailboxStatus::Paired;
                    Ok(MailboxTransition {
                        state: Some(next),
                        effects: vec![MailboxEffect::Claimed {
                            membership: Membership::Claimant,
                            expires_at: state.expires_at,
                        }],
                    })
                }
                Some(claimant) if claimant.hash == claimant_hash => Ok(MailboxTransition {
                    state: Some(next),
                    effects: vec![MailboxEffect::Claimed {
                        membership: Membership::Claimant,
                        expires_at: state.expires_at,
                    }],
                }),
                Some(_) => Ok(next.terminate(CloseReason::Crowded)),
            }
        }
        MailboxCommand::Open { membership_hash } => {
            let membership = next
                .membership_for_hash(membership_hash)
                .ok_or(MailboxError::NotMember)?;
            let mut effects = vec![MailboxEffect::Opened {
                membership,
                expires_at: state.expires_at,
            }];
            if let Some(peer) = next.member(membership.peer()) {
                effects.extend(peer.frames.iter().filter_map(|frame| {
                    frame.body.as_ref().map(|body| MailboxEffect::Deliver {
                        recipient: membership,
                        peer_seq: frame.seq,
                        body: body.clone(),
                    })
                }));
            }
            Ok(MailboxTransition {
                state: Some(next),
                effects,
            })
        }
        MailboxCommand::Put { sender, seq, body } => {
            if body.is_empty() || body.len() > MAX_FRAME_BODY_BYTES {
                return Err(MailboxError::BodySize);
            }
            let digest: [u8; 32] = Sha256::digest(&body).into();
            let member = next.member(sender).ok_or(MailboxError::NotMember)?;
            if seq < member.next_seq {
                let frame = member
                    .frames
                    .iter()
                    .find(|frame| frame.seq == seq)
                    .ok_or(MailboxError::UnknownSequence)?;
                if frame.body_len == body.len() && frame.digest == digest {
                    return Ok(MailboxTransition {
                        state: Some(next),
                        effects: vec![MailboxEffect::Stored {
                            sender,
                            seq,
                            replay: true,
                        }],
                    });
                }
                return Ok(next.terminate(CloseReason::Conflict));
            }
            if seq > member.next_seq {
                return Err(MailboxError::SequenceGap {
                    expected: member.next_seq,
                    got: seq,
                });
            }
            if usize::from(seq) >= MAX_FRAMES_PER_MEMBERSHIP
                || member.frames.len() >= MAX_FRAMES_PER_MEMBERSHIP
            {
                return Err(MailboxError::FrameLimit);
            }

            let member = next.member_mut(sender).ok_or(MailboxError::NotMember)?;
            member.frames.push(FrameRecord {
                seq,
                digest,
                body_len: body.len(),
                body: Some(body.clone()),
            });
            member.next_seq += 1;

            let mut effects = vec![MailboxEffect::Stored {
                sender,
                seq,
                replay: false,
            }];
            if next.member(sender.peer()).is_some() {
                effects.push(MailboxEffect::Deliver {
                    recipient: sender.peer(),
                    peer_seq: seq,
                    body,
                });
            }
            Ok(MailboxTransition {
                state: Some(next),
                effects,
            })
        }
        MailboxCommand::Ack { sender, peer_seq } => {
            if next.member(sender).is_none() {
                return Err(MailboxError::NotMember);
            }
            let owner = sender.peer();
            let peer = next
                .member_mut(owner)
                .ok_or(MailboxError::UnknownSequence)?;
            let frame = peer
                .frames
                .iter_mut()
                .find(|frame| frame.seq == peer_seq)
                .ok_or(MailboxError::UnknownSequence)?;
            let effects = if frame.body.take().is_some() {
                vec![MailboxEffect::BodyDeleted {
                    owner,
                    seq: peer_seq,
                }]
            } else {
                Vec::new()
            };
            Ok(MailboxTransition {
                state: Some(next),
                effects,
            })
        }
        MailboxCommand::Close { sender } => {
            if next.member(sender).is_none() {
                return Err(MailboxError::NotMember);
            }
            Ok(next.terminate(CloseReason::Closed))
        }
    }
}

/// Reap a mailbox at its original expiry without extending retention.
pub fn reap(state: &Mailbox, now: u64) -> Result<MailboxTransition, MailboxError> {
    if now < state.expires_at {
        return Ok(MailboxTransition {
            state: Some(state.clone()),
            effects: Vec::new(),
        });
    }
    let mut expired = state.clone();
    let mut effects = Vec::new();
    expired.delete_bodies(&mut effects);
    if !matches!(expired.status, MailboxStatus::Terminal(_)) {
        effects.push(MailboxEffect::Terminal(CloseReason::Expired));
    }
    Ok(MailboxTransition {
        state: None,
        effects,
    })
}
