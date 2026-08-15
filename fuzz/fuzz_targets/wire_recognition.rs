#![no_main]

use cbcl_pairing::wire::{
    decode_application_payload, decode_channel_frame, decode_client_message, decode_invitation,
    decode_pairing_decision, decode_pairing_intent, decode_sealed_plaintext, decode_server_message,
    encode_application_payload, encode_channel_frame, encode_client_message, encode_invitation,
    encode_pairing_decision, encode_pairing_intent, encode_sealed_plaintext, encode_server_message,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(value) = decode_invitation(input) {
        assert_eq!(encode_invitation(&value).expect("invitation"), input);
    }
    if let Ok(value) = decode_client_message(input) {
        assert_eq!(encode_client_message(&value).expect("client"), input);
    }
    if let Ok(value) = decode_server_message(input) {
        assert_eq!(encode_server_message(&value).expect("server"), input);
    }
    if let Ok(value) = decode_channel_frame(input) {
        assert_eq!(encode_channel_frame(&value).expect("channel"), input);
    }
    if let Ok(value) = decode_sealed_plaintext(input) {
        assert_eq!(encode_sealed_plaintext(&value).expect("plaintext"), input);
    }
    if let Ok(value) = decode_pairing_intent(input) {
        assert_eq!(encode_pairing_intent(&value).expect("intent"), input);
    }
    if let Ok(value) = decode_pairing_decision(input) {
        assert_eq!(encode_pairing_decision(&value).expect("decision"), input);
    }
    if let Ok(value) = decode_application_payload(input) {
        assert_eq!(encode_application_payload(&value).expect("payload"), input);
    }
});
