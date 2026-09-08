#![no_main]

use cbcl_pairing::credential_v2::CredentialV2AccountSelect;
use libfuzzer_sys::fuzz_target;

// SPEC-080 CON-001: recognition is total and canonical — whatever decodes
// re-encodes to the exact input bytes, and nothing panics.
fuzz_target!(|input: &[u8]| {
    if let Ok(selection) = CredentialV2AccountSelect::decode(input) {
        assert_eq!(selection.encode(), input);
        assert!(selection.object().is_ok());
    }
});
