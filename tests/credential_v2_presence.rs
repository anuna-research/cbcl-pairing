//! SPEC-001 TEST-060: credential/v2 keeps machine carrier and human presence disjoint.

use cbcl_pairing::credential_v2::CredentialV2PresenceCode;

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
}
