//! Effectful, application-unaware mailbox persistence adapters.
//!
//! Stores receive only [`MailboxSnapshot`] data: locator metadata, membership
//! hashes, sequence metadata, expiry, and opaque queued bodies. Raw membership
//! tokens and application semantics cannot cross this interface.

use crate::{
    mailbox::{
        Mailbox, MailboxError, MailboxSnapshot, MailboxStatus, Membership, MembershipHash,
        SequenceSnapshot,
    },
    wire::CloseReason,
};
use ciborium::Value;
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

const STORE_DOMAIN: &str = "cbcl-pairing-mailbox-store/v1";

/// Closed mailbox-store failure taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Filesystem or durable-write operation failed.
    Io,
    /// Stored bytes were malformed, non-canonical, or violated mailbox invariants.
    Malformed,
    /// Two stored records claimed the same mailbox identifier.
    Conflict,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

/// Durable boundary used by the reference relay.
pub trait MailboxStore: Send {
    /// Load and fully recognise every retained mailbox during startup.
    fn load(&mut self) -> Result<Vec<Mailbox>, StoreError>;

    /// Atomically replace one complete mailbox record.
    fn put(&mut self, mailbox: &Mailbox) -> Result<(), StoreError>;

    /// Durably delete one mailbox record.
    fn remove(&mut self, mailbox_id: [u8; 32]) -> Result<(), StoreError>;
}

/// In-memory adapter used by tests and ephemeral deployments.
#[derive(Default)]
pub struct MemoryMailboxStore {
    records: BTreeMap<[u8; 32], Vec<u8>>,
}

impl fmt::Debug for MemoryMailboxStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryMailboxStore")
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MailboxStore for MemoryMailboxStore {
    fn load(&mut self) -> Result<Vec<Mailbox>, StoreError> {
        self.records.values().map(|bytes| decode(bytes)).collect()
    }

    fn put(&mut self, mailbox: &Mailbox) -> Result<(), StoreError> {
        let snapshot = mailbox.snapshot();
        self.records.insert(snapshot.mailbox_id, encode(&snapshot)?);
        Ok(())
    }

    fn remove(&mut self, mailbox_id: [u8; 32]) -> Result<(), StoreError> {
        self.records.remove(&mailbox_id);
        Ok(())
    }
}

/// Directory-backed store with canonical records and atomic replacement.
pub struct FileMailboxStore {
    directory: PathBuf,
}

impl fmt::Debug for FileMailboxStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileMailboxStore")
            .field("directory", &"REDACTED")
            .finish()
    }
}

impl FileMailboxStore {
    /// Open or create one private store directory.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        fs::create_dir_all(directory.as_ref()).map_err(|_| StoreError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.as_ref(), fs::Permissions::from_mode(0o700))
                .map_err(|_| StoreError::Io)?;
        }
        Ok(Self {
            directory: directory.as_ref().to_path_buf(),
        })
    }

    fn path(&self, mailbox_id: [u8; 32]) -> PathBuf {
        self.directory
            .join(format!("{}.cbor", lower_hex(&mailbox_id)))
    }

    fn sync_directory(&self) -> Result<(), StoreError> {
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Io)
    }
}

impl MailboxStore for FileMailboxStore {
    fn load(&mut self) -> Result<Vec<Mailbox>, StoreError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(|_| StoreError::Io)? {
            let entry = entry.map_err(|_| StoreError::Io)?;
            let path = entry.path();
            if is_store_temporary(&path) {
                fs::remove_file(&path).map_err(|_| StoreError::Io)?;
                self.sync_directory()?;
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("cbor") {
                continue;
            }
            let bytes = fs::read(&path).map_err(|_| StoreError::Io)?;
            let mailbox = decode(&bytes)?;
            let expected = format!("{}.cbor", lower_hex(&mailbox.snapshot().mailbox_id));
            if path.file_name().and_then(|value| value.to_str()) != Some(expected.as_str()) {
                return Err(StoreError::Malformed);
            }
            records.push(mailbox);
        }
        records.sort_by_key(|mailbox| mailbox.snapshot().mailbox_id);
        Ok(records)
    }

    fn put(&mut self, mailbox: &Mailbox) -> Result<(), StoreError> {
        let snapshot = mailbox.snapshot();
        let target = self.path(snapshot.mailbox_id);
        let temporary = self.directory.join(format!(
            ".{}.{}.tmp",
            lower_hex(&snapshot.mailbox_id),
            std::process::id()
        ));
        let bytes = encode(&snapshot)?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|_| StoreError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|_| StoreError::Io)?;
            }
            file.write_all(&bytes).map_err(|_| StoreError::Io)?;
            file.sync_all().map_err(|_| StoreError::Io)?;
            fs::rename(&temporary, target).map_err(|_| StoreError::Io)?;
            self.sync_directory()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn remove(&mut self, mailbox_id: [u8; 32]) -> Result<(), StoreError> {
        match fs::remove_file(self.path(mailbox_id)) {
            Ok(()) => self.sync_directory(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Io),
        }
    }
}

fn encode(snapshot: &MailboxSnapshot) -> Result<Vec<u8>, StoreError> {
    let status = match snapshot.status {
        MailboxStatus::Waiting => Value::Array(vec![Value::Integer(0.into())]),
        MailboxStatus::Paired => Value::Array(vec![Value::Integer(1.into())]),
        MailboxStatus::Terminal(reason) => Value::Array(vec![
            Value::Integer(2.into()),
            Value::Integer(close_number(reason).into()),
        ]),
    };
    let sequences = snapshot
        .sequences
        .iter()
        .map(|sequence| {
            Ok(Value::Array(vec![
                Value::Integer(membership_number(sequence.owner).into()),
                Value::Integer(u64::from(sequence.seq).into()),
                Value::Bytes(sequence.body_digest.to_vec()),
                Value::Integer(
                    u64::try_from(sequence.body_len)
                        .map_err(|_| StoreError::Malformed)?
                        .into(),
                ),
                sequence
                    .body
                    .as_ref()
                    .map_or(Value::Null, |body| Value::Bytes(body.clone())),
            ]))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    cbor2::to_canonical_vec(&Value::Array(vec![
        Value::Text(STORE_DOMAIN.into()),
        Value::Bytes(snapshot.mailbox_id.to_vec()),
        snapshot
            .nameplate
            .map_or(Value::Null, |value| Value::Integer(u64::from(value).into())),
        Value::Integer(snapshot.expires_at.into()),
        status,
        Value::Array(
            snapshot
                .membership_hashes
                .iter()
                .map(|hash| Value::Bytes(hash.into_bytes().to_vec()))
                .collect(),
        ),
        Value::Array(sequences),
    ]))
    .map_err(|_| StoreError::Malformed)
}

fn decode(input: &[u8]) -> Result<Mailbox, StoreError> {
    let value: Value =
        ciborium::de::from_reader(Cursor::new(input)).map_err(|_| StoreError::Malformed)?;
    if cbor2::to_canonical_vec(&value).map_err(|_| StoreError::Malformed)? != input {
        return Err(StoreError::Malformed);
    }
    let Value::Array(parts) = value else {
        return Err(StoreError::Malformed);
    };
    let [domain, mailbox_id, nameplate, expires_at, status, hashes, sequences] = parts.as_slice()
    else {
        return Err(StoreError::Malformed);
    };
    if domain.as_text() != Some(STORE_DOMAIN) {
        return Err(StoreError::Malformed);
    }
    let mailbox_id = fixed::<32>(mailbox_id)?;
    let nameplate = match nameplate {
        Value::Null => None,
        value => Some(
            integer(value)?
                .try_into()
                .map_err(|_| StoreError::Malformed)?,
        ),
    };
    let status = decode_status(status)?;
    let Value::Array(hashes) = hashes else {
        return Err(StoreError::Malformed);
    };
    let membership_hashes = hashes
        .iter()
        .map(|value| fixed::<32>(value).map(MembershipHash::new))
        .collect::<Result<Vec<_>, _>>()?;
    let Value::Array(sequences) = sequences else {
        return Err(StoreError::Malformed);
    };
    let sequences = sequences
        .iter()
        .map(decode_sequence)
        .collect::<Result<Vec<_>, _>>()?;
    Mailbox::from_snapshot(MailboxSnapshot {
        mailbox_id,
        nameplate,
        expires_at: integer(expires_at)?,
        status,
        membership_hashes,
        sequences,
    })
    .map_err(|_| StoreError::Malformed)
}

fn decode_status(value: &Value) -> Result<MailboxStatus, StoreError> {
    let Value::Array(parts) = value else {
        return Err(StoreError::Malformed);
    };
    match parts.as_slice() {
        [kind] if integer(kind)? == 0 => Ok(MailboxStatus::Waiting),
        [kind] if integer(kind)? == 1 => Ok(MailboxStatus::Paired),
        [kind, reason] if integer(kind)? == 2 => {
            Ok(MailboxStatus::Terminal(close_reason(integer(reason)?)?))
        }
        _ => Err(StoreError::Malformed),
    }
}

fn decode_sequence(value: &Value) -> Result<SequenceSnapshot, StoreError> {
    let Value::Array(parts) = value else {
        return Err(StoreError::Malformed);
    };
    let [owner, seq, digest, body_len, body] = parts.as_slice() else {
        return Err(StoreError::Malformed);
    };
    Ok(SequenceSnapshot {
        owner: match integer(owner)? {
            0 => Membership::Allocator,
            1 => Membership::Claimant,
            _ => return Err(StoreError::Malformed),
        },
        seq: integer(seq)?
            .try_into()
            .map_err(|_| StoreError::Malformed)?,
        body_digest: fixed::<32>(digest)?,
        body_len: integer(body_len)?
            .try_into()
            .map_err(|_| StoreError::Malformed)?,
        body: match body {
            Value::Null => None,
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => return Err(StoreError::Malformed),
        },
    })
}

fn integer(value: &Value) -> Result<u64, StoreError> {
    let Value::Integer(value) = value else {
        return Err(StoreError::Malformed);
    };
    u64::try_from(*value).map_err(|_| StoreError::Malformed)
}

fn fixed<const LENGTH: usize>(value: &Value) -> Result<[u8; LENGTH], StoreError> {
    let Value::Bytes(bytes) = value else {
        return Err(StoreError::Malformed);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Malformed)
}

const fn membership_number(value: Membership) -> u64 {
    match value {
        Membership::Allocator => 0,
        Membership::Claimant => 1,
    }
}

const fn close_number(value: CloseReason) -> u64 {
    match value {
        CloseReason::Closed => 0,
        CloseReason::Crowded => 1,
        CloseReason::Expired => 2,
        CloseReason::Conflict => 3,
    }
}

fn close_reason(value: u64) -> Result<CloseReason, StoreError> {
    match value {
        0 => Ok(CloseReason::Closed),
        1 => Ok(CloseReason::Crowded),
        2 => Ok(CloseReason::Expired),
        3 => Ok(CloseReason::Conflict),
        _ => Err(StoreError::Malformed),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn is_store_temporary(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((mailbox, process)) = body.split_once('.') else {
        return false;
    };
    mailbox.len() == 64
        && mailbox
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !process.is_empty()
        && process.bytes().all(|byte| byte.is_ascii_digit())
}

impl From<MailboxError> for StoreError {
    fn from(_: MailboxError) -> Self {
        Self::Malformed
    }
}
