//! Pure two-membership mailbox state and transition effects.

use crate::wire::CloseReason;

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
            Self::NotMember => 404,
            Self::Closed(_) => 410,
            Self::BodySize => 413,
            Self::NotImplemented => 503,
            Self::LifetimeOutOfRange
            | Self::ExpiryOverflow
            | Self::NameplateOutOfRange
            | Self::SequenceGap { .. }
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
    pub fn allocate(_input: AllocationInput) -> Result<Self, MailboxError> {
        Err(MailboxError::NotImplemented)
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
}

/// Apply one recognised command to immutable mailbox input.
pub fn transition(
    _state: &Mailbox,
    _now: u64,
    _command: MailboxCommand,
) -> Result<MailboxTransition, MailboxError> {
    Err(MailboxError::NotImplemented)
}

/// Reap a mailbox at its original expiry without extending retention.
pub fn reap(_state: &Mailbox, _now: u64) -> Result<MailboxTransition, MailboxError> {
    Err(MailboxError::NotImplemented)
}
