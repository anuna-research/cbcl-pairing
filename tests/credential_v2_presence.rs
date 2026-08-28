//! SPEC-001 TEST-060: credential/v2 keeps machine carrier and human presence disjoint.

use cbcl_pairing::{
    credential_v2::{CredentialV2Carrier, CredentialV2CarrierInput, CredentialV2PresenceCode},
    wire::{claim_commitment, ClaimToken},
};

#[test]
fn pair1_round_trips_independent_secrets_and_rejects_every_substitution() {
    let canonical = CredentialV2PresenceCode::new([0x11; 16], [0x22; 16]).to_string();
    assert_eq!(canonical.len(), 71);
    assert_eq!(canonical.split('-').count(), 12);
    assert!(canonical.parse::<CredentialV2PresenceCode>().is_ok());
    assert!(canonical
        .to_ascii_lowercase()
        .parse::<CredentialV2PresenceCode>()
        .is_ok());

    let mut checksum_changed = canonical.clone().into_bytes();
    checksum_changed[6] = if checksum_changed[6] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert!(String::from_utf8(checksum_changed)
        .unwrap()
        .parse::<CredentialV2PresenceCode>()
        .is_err());

    let mut nonzero_padding = canonical.clone().into_bytes();
    let last = nonzero_padding.last_mut().unwrap();
    *last = if *last == b'1' { b'2' } else { b'1' };
    assert!(String::from_utf8(nonzero_padding)
        .unwrap()
        .parse::<CredentialV2PresenceCode>()
        .is_err());

    for refused in [
        canonical.replace('0', "O"),
        canonical.replace('-', ""),
        format!(" {canonical}"),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
    ] {
        assert!(refused.parse::<CredentialV2PresenceCode>().is_err(), "{refused}");
    }

    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://chat.anuna.io/selfsame/v2".into(),
        relay_origin: "https://chat.anuna.io:9443".into(),
        mailbox_id: [0x31; 32],
        carrier_ceremony_id: [0x32; 32],
        carrier_nonce: [0x33; 32],
        claim_commitment: claim_commitment([0x31; 32], &ClaimToken::new([0x22; 16])),
        relay_expires_at: 1_800_000_900,
        expected_allocator_key: None,
    })
    .unwrap();
    assert!(CredentialV2PresenceCode::new([0x11; 16], [0x22; 16])
        .bind_to_carrier(&carrier)
        .is_ok());
    assert!(CredentialV2PresenceCode::new([0x11; 16], [0x23; 16])
        .bind_to_carrier(&carrier)
        .is_err());
}
