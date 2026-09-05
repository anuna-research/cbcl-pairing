//! Authenticated inner state tests for SPEC-078 CON-003 / TEST-003/006.
use super::*;
use crate::{
    credential_v2::CredentialV2ManualWords,
    wire::{claim_commitment, ClaimToken},
};
const NOW: u64 = 1_800_000_000;
const KEY: [u8; 32] = [0x41; 32];
fn bootstrap(mode: CredentialV2AllocatorMode) -> CredentialV2AllocatorBootstrap {
    let c = *CredentialV2ManualWords::from_csprng([0x12, 0x34, 0x56, 0x78]).cpace_secret();
    let carrier = CredentialV2Carrier::new(super::super::CredentialV2CarrierInput {
        application_context: "https://a.b/a".into(),
        relay_origin: "https://r".into(),
        mailbox_id: [0x11; 32],
        carrier_ceremony_id: [0x12; 32],
        carrier_nonce: [0x13; 32],
        claim_commitment: claim_commitment([0x11; 32], &ClaimToken::new([0x14; 16])),
        relay_expires_at: NOW + 900,
        expected_allocator_key: Some([0x15; 32]),
    })
    .unwrap();
    CredentialV2AllocatorBootstrap::new(
        carrier,
        CredentialV2Presence::new(c, [0x14; 16]),
        [0x16; 32],
        CredentialV2RelayState::new([0x17; 32]),
        mode,
    )
    .unwrap()
}
fn seal(s: &CredentialV2AllocatorBootstrap, plain: &[u8]) -> EndpointCheckpointV2 {
    seal_checkpoint_plaintext(
        plain,
        Side::Allocator,
        &s.carrier,
        &KEY,
        1,
        Some(NOW + 900),
        [0x42; 12],
    )
    .unwrap()
}
fn restore(
    s: &CredentialV2AllocatorBootstrap,
    bytes: &[u8],
    mode: CredentialV2AllocatorMode,
) -> Result<CredentialV2AllocatorBootstrap, CredentialV2Error> {
    let restored = CredentialV2AllocatorBootstrap::restore_checkpoint(bytes, &KEY, &s.carrier, 1, NOW, mode);
    let inspected = super::super::CredentialV2AllocatorCheckpointInspection::inspect(
        bytes, &KEY, &s.carrier, 1, *s.profile_digest(), NOW + 901, mode, Box::new(NoInspectionBodies),
    );
    assert_eq!(inspected.is_ok(), restored.is_ok(), "inspection retains every inner-state/old-mode check");
    if let Ok(view) = inspected {
        assert_eq!(view.bootstrap_phase(), Some(restored.as_ref().unwrap().phase()));
        assert_eq!(view.bootstrap_mode(), Some(restored.as_ref().unwrap().mode()));
    }
    restored
}

#[derive(Debug)]
struct NoInspectionBodies;
impl super::super::CredentialV2BodyVerifier for NoInspectionBodies {
    fn verify(&mut self, _: &super::super::CredentialV2LogicalBody<'_>) -> Result<(), CredentialV2Error> {
        Err(CredentialV2Error::Phase)
    }
}

#[test]
fn closure_inspection_rejects_authenticated_outer_expiry_shape_substitution() {
    use super::super::CredentialV2AllocatorCheckpointInspection as Inspection;
    for mode in [CredentialV2AllocatorMode::Full, CredentialV2AllocatorMode::Manual] {
        let s = bootstrap(mode);
        let plaintext = s.encode_inner(1, [0x42; 12]).unwrap();
        for expiry in [None, Some(NOW + 899), Some(NOW + 901)] {
            let sealed = seal_checkpoint_plaintext(&plaintext, Side::Allocator, &s.carrier,
                &KEY, 1, expiry, [0x42; 12]).unwrap();
            assert!(Inspection::inspect(sealed.as_bytes(), &KEY, &s.carrier, 1,
                *s.profile_digest(), u64::MAX, mode, Box::new(NoInspectionBodies)).is_err());
        }
    }
}
#[test]
fn inner_tag_is_exact_v3_mode_only_and_old_v2_restores_full_only() {
    let full = bootstrap(CredentialV2AllocatorMode::Full);
    let manual = bootstrap(CredentialV2AllocatorMode::Manual);
    let f = full.encode_inner(1, [0x42; 12]).unwrap();
    let m = manual.encode_inner(1, [0x42; 12]).unwrap();
    assert_eq!(&f[..36], b"cbcl-pairing allocator bootstrap/v3\0");
    assert_eq!(&m[..36], b"cbcl-pairing allocator bootstrap/v3\x01");
    assert_eq!(
        &f[36..],
        &m[36..],
        "every subsequent field retains its old order and encoding"
    );
    let mut old = f.to_vec();
    old[..36].copy_from_slice(b"cbcl-pairing allocator bootstrap/v2\0");
    let sealed = seal(&full, &old);
    let restored = restore(&full, sealed.as_bytes(), CredentialV2AllocatorMode::Full).unwrap();
    assert_eq!(restored.mode(), CredentialV2AllocatorMode::Full);
    assert!(restored.handoff().unwrap().is_some());
    assert!(restored.manual_transfer_text().is_err());
    assert!(restore(&full, sealed.as_bytes(), CredentialV2AllocatorMode::Manual).is_err());
    for mode in [
        CredentialV2AllocatorMode::Full,
        CredentialV2AllocatorMode::Manual,
    ] {
        let s = bootstrap(mode);
        let original = s.encode_inner(1, [0x42; 12]).unwrap();
        let other = if mode == CredentialV2AllocatorMode::Full {
            CredentialV2AllocatorMode::Manual
        } else {
            CredentialV2AllocatorMode::Full
        };
        assert!(restore(&s, seal(&s, &original).as_bytes(), other).is_err());
        for tag in [0, 1, 2, 255] {
            let mut wrong = original.to_vec();
            wrong[35] = tag;
            if wrong == *original {
                continue;
            }
            assert!(restore(&s, seal(&s, &wrong).as_bytes(), mode).is_err());
        }
        let sealed = seal(&s, &original);
        let mut outer: ciborium::Value = ciborium::de::from_reader(sealed.as_bytes()).unwrap();
        let members = outer.as_array_mut().unwrap();
        assert_eq!(members.len(), 9);
        assert_eq!(
            members[0].as_text(),
            Some("cbcl-pairing-endpoint-checkpoint/v2")
        );
        assert_eq!(
            members[4].as_bytes().unwrap(),
            s.carrier.carrier_ceremony_id()
        );
        let ciphertext = members[8].as_bytes_mut().unwrap();
        ciphertext[35] ^= 1; // Alter only the encrypted mode, without re-authentication.
        let wrong = cbor2::to_canonical_vec(&outer).unwrap();
        assert!(restore(&s, &wrong, mode).is_err());
    }
}
#[test]
fn retained_scalar_and_cached_share_are_checked_before_any_recovered_output() {
    let mut s = bootstrap(CredentialV2AllocatorMode::Manual);
    let context = CredentialV2Context::derive(&s.carrier, s.profile_digest).unwrap();
    let (_, message) = context
        .start_cpace(Side::Claimant, &s.presence, [0x51; 32])
        .unwrap();
    let peer = CredentialV2Frame::cpace(&message).unwrap();
    s.claimant_admitted().unwrap();
    s.start_cpace([0x52; 32]).unwrap();
    s.retain_peer_cpace(&peer).unwrap();
    let original = s.encode_inner(1, [0x42; 12]).unwrap();
    let restored = restore(
        &s,
        seal(&s, &original).as_bytes(),
        CredentialV2AllocatorMode::Manual,
    )
    .unwrap();
    assert_eq!(restored.peer_cpace(), Some(&peer));
    assert_eq!(restored.fresh_scalar.as_deref(), Some(&[0x52; 32]));
    assert!(restored.presence.checkpoint_parts().1.is_none());
    for finished in [false, true] {
        if finished {
            s.prepare_finished().unwrap();
        }
        let original_scalar = s.fresh_scalar.take();
        s.fresh_scalar = Some(Zeroizing::new([0x53; 32]));
        let bad = s.encode_inner(1, [0x42; 12]).unwrap();
        assert!(restore(
            &s,
            seal(&s, &bad).as_bytes(),
            CredentialV2AllocatorMode::Manual
        )
        .is_err());
        s.fresh_scalar = original_scalar;
        let original_frame = s.cached_outbound.clone();
        match s.cached_outbound.as_mut().unwrap() {
            CredentialV2Frame::Cpace(message) => message.share[0] ^= 1,
            CredentialV2Frame::Finished { value, .. } => value[0] ^= 1,
            _ => unreachable!(),
        }
        let bad = s.encode_inner(1, [0x42; 12]).unwrap();
        assert!(restore(
            &s,
            seal(&s, &bad).as_bytes(),
            CredentialV2AllocatorMode::Manual
        )
        .is_err());
        s.cached_outbound = original_frame;
    }
}

#[test]
fn every_old_bootstrap_phase_restores_only_full_with_exact_cached_frames() {
    let mut s = bootstrap(CredentialV2AllocatorMode::Full);
    let context = CredentialV2Context::derive(&s.carrier, s.profile_digest).unwrap();
    let (_, message) = context
        .start_cpace(Side::Claimant, &s.presence, [0x61; 32])
        .unwrap();
    let peer = CredentialV2Frame::cpace(&message).unwrap();
    for phase in 0..4 {
        match phase {
            0 => (),
            1 => s.claimant_admitted().unwrap(),
            2 => {
                s.start_cpace([0x62; 32]).unwrap();
            }
            3 => {
                s.receive_cpace(&peer).unwrap();
            }
            _ => unreachable!(),
        }
        let mut old = s.encode_inner(1, [0x42; 12]).unwrap();
        old[..36].copy_from_slice(b"cbcl-pairing allocator bootstrap/v2\0");
        let sealed = seal(&s, &old);
        let restored = restore(&s, sealed.as_bytes(), CredentialV2AllocatorMode::Full).unwrap();
        assert_eq!(restored.phase(), s.phase());
        assert_eq!(restored.mode(), CredentialV2AllocatorMode::Full);
        assert_eq!(restored.cached_outbound_frame(), s.cached_outbound_frame());
        assert_eq!(restored.peer_cpace(), s.peer_cpace());
        assert!(restore(&s, sealed.as_bytes(), CredentialV2AllocatorMode::Manual).is_err());
    }
}
