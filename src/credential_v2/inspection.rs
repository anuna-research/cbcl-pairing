//! Authenticated closure facts from a saved allocator, with no live capability.
use super::{
    decode_object, CredentialV2AllocatorBootstrap, CredentialV2AllocatorBootstrapPhase,
    CredentialV2AllocatorMode, CredentialV2BodyVerifier, CredentialV2Carrier, CredentialV2Error,
    CredentialV2Object, CredentialV2Phase,
};
use crate::wire::Side;

/// Read-only authenticated facts for obtaining closure of a saved invitation.
///
/// Inspection may authenticate an elapsed checkpoint, but it never restores a
/// live session or exposes C, T, scalar, traffic keys, relay membership, or a
/// cached frame. The temporary bootstrap/channel is erased before return.
/// The consumer must still obtain exact authenticated hub closure before deletion.
///
/// There is no protocol-entry or secret-export surface:
/// ```compile_fail
/// use cbcl_pairing::credential_v2::CredentialV2AllocatorCheckpointInspection;
/// fn resume(saved: CredentialV2AllocatorCheckpointInspection) { saved.start(); }
/// ```
/// ```compile_fail
/// use cbcl_pairing::credential_v2::CredentialV2AllocatorCheckpointInspection;
/// fn export(saved: CredentialV2AllocatorCheckpointInspection) { saved.handoff_text(); }
/// ```
pub struct CredentialV2AllocatorCheckpointInspection {
    bootstrap: Option<(
        CredentialV2AllocatorBootstrapPhase,
        CredentialV2AllocatorMode,
    )>,
    endpoint: Option<CredentialV2Phase>,
    transcript_hash: Option<[u8; 64]>,
    last_received: Option<CredentialV2Object>,
    terminal_receipt: Option<([u8; 32], [u8; 32])>,
    receipt_commitment: Option<[u8; 32]>,
    expired: bool,
}

impl std::fmt::Debug for CredentialV2AllocatorCheckpointInspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialV2AllocatorCheckpointInspection([REDACTED])")
    }
}

impl CredentialV2AllocatorCheckpointInspection {
    /// Authenticate the same carrier, generation, mode and state bindings as
    /// ordinary restore, without granting its execution authority. Bootstrap
    /// profile digest is checked directly; established application bindings are
    /// checked by the caller's retained body-state verifier, as in live restore.
    /// `now` is the real caller clock, used only for a non-authoritative expiry hint.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect(
        checkpoint: &[u8],
        wrapping_key: &[u8; 32],
        carrier: &CredentialV2Carrier,
        expected_generation: u64,
        expected_profile_digest: [u8; 32],
        now: u64,
        expected_mode: CredentialV2AllocatorMode,
        body_verifier: Box<dyn CredentialV2BodyVerifier>,
    ) -> Result<Self, CredentialV2Error> {
        let expired = now >= carrier.relay_expires_at();
        if let Ok(bootstrap) = CredentialV2AllocatorBootstrap::inspect_checkpoint(
            checkpoint,
            wrapping_key,
            carrier,
            expected_generation,
            expected_mode,
        ) {
            if bootstrap.profile_digest() != &expected_profile_digest {
                return Err(CredentialV2Error::Profile);
            }
            return Ok(Self {
                bootstrap: Some((bootstrap.phase(), bootstrap.mode())),
                endpoint: None,
                transcript_hash: None,
                last_received: None,
                terminal_receipt: None,
                receipt_commitment: None,
                expired,
            });
        }
        let restored = super::checkpoint::inspect_allocator_endpoint(
            checkpoint,
            wrapping_key,
            carrier,
            expected_generation,
            body_verifier,
        )?;
        let (endpoint, channel, _relay) = restored.into_parts();
        let last_received = endpoint
            .last
            .as_ref()
            .filter(|last| last.sender != Side::Allocator)
            .and_then(|last| last.bytes.as_deref())
            .map(decode_object)
            .transpose()?;
        let terminal_receipt = if endpoint.receipt_released() {
            endpoint
                .last
                .as_ref()
                .map(|last| (last.intent_digest, last.content_hash))
        } else {
            None
        };
        Ok(Self {
            bootstrap: None,
            endpoint: Some(endpoint.phase()),
            transcript_hash: Some(channel.transcript_hash()),
            last_received,
            terminal_receipt,
            receipt_commitment: Some(channel.receipt_recovery_commitment(carrier)?),
            expired,
        })
    }

    /// Authenticated bootstrap phase, absent after establishment.
    #[must_use]
    pub fn bootstrap_phase(&self) -> Option<CredentialV2AllocatorBootstrapPhase> {
        self.bootstrap.map(|(phase, _)| phase)
    }
    /// Authenticated bootstrap mode; established metadata cannot supply one.
    #[must_use]
    pub fn bootstrap_mode(&self) -> Option<CredentialV2AllocatorMode> {
        self.bootstrap.map(|(_, mode)| mode)
    }
    /// Authenticated application phase, absent during bootstrap.
    #[must_use]
    pub const fn endpoint_phase(&self) -> Option<CredentialV2Phase> {
        self.endpoint
    }
    /// Retained public transcript binding, without channel or exporter keys.
    #[must_use]
    pub const fn transcript_hash(&self) -> Option<[u8; 64]> {
        self.transcript_hash
    }
    /// Borrow only the last authenticated received object for consumer status
    /// verification. A locally authored Receipt is never presented as a Payload.
    #[must_use]
    pub const fn last_received_object(&self) -> Option<&CredentialV2Object> {
        self.last_received.as_ref()
    }
    /// Authenticated intent and content hash of the locally authored terminal
    /// Receipt. Its plaintext may have been retired after send acknowledgement.
    /// The consumer must match a reconstructed canonical Receipt against both
    /// digests before trusting its candidate final status, and verify that status.
    /// This proves the sealed transition, not physical relay delivery.
    #[must_use]
    pub const fn terminal_receipt_binding(&self) -> Option<([u8; 32], [u8; 32])> {
        self.terminal_receipt
    }
    /// Existing public receipt-recovery commitment, never the recovery token.
    #[must_use]
    pub const fn receipt_recovery_commitment(&self) -> Option<[u8; 32]> {
        self.receipt_commitment
    }
    /// A local expiry hint only: this is not authenticated hub closure and must
    /// never authorize deletion, replacement, or protocol execution.
    #[must_use]
    pub const fn is_expired(&self) -> bool {
        self.expired
    }
}
