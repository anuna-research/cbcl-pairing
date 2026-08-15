//! Official revision-21 CPace255 conformance vectors and lifecycle tests.

use cbcl_pairing::{
    cpace::{
        calculate_generator, finish, generator_string, start, x25519_scalar_mult_vfy, CpaceError,
    },
    wire::Side,
};

const PRS: &[u8] = b"Password";
const CI: &[u8] = b"\x0bA_initiator\x0bB_responder";

fn bytes(hexadecimal: &str) -> Vec<u8> {
    hex::decode(hexadecimal).expect("valid test-vector hex")
}

fn bytes32(hexadecimal: &str) -> [u8; 32] {
    bytes(hexadecimal)
        .try_into()
        .expect("32-byte test-vector value")
}

fn sid() -> [u8; 16] {
    bytes("7e4b4791d6a8ef019b936c79fb7f2c57")
        .try_into()
        .expect("16-byte sid")
}

#[test]
fn official_cpace255_generator_and_exchange_vector() {
    let sid = sid();
    let generator = calculate_generator(PRS, CI, &sid).expect("generator");
    assert_eq!(
        generator,
        bytes32("d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f")
    );

    let ya = bytes32("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080");
    let yb = bytes32("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a");
    let (a_state, a_message) = start(Side::Allocator, PRS, CI, &sid, b"ADa", ya).expect("start A");
    let (b_state, b_message) = start(Side::Claimant, PRS, CI, &sid, b"ADb", yb).expect("start B");

    assert_eq!(
        a_message.share,
        bytes32("1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32")
    );
    assert_eq!(
        b_message.share,
        bytes32("248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623")
    );
    assert_eq!(
        x25519_scalar_mult_vfy(ya, b_message.share).expect("shared point"),
        bytes32("5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b")
    );

    let a_key = finish(a_state, &b_message).expect("finish A");
    let b_key = finish(b_state, &a_message).expect("finish B");
    let expected = bytes(
        "6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2\
         aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263",
    );
    assert_eq!(a_key.as_bytes().as_slice(), expected);
    assert_eq!(a_key, b_key);
}

#[test]
fn generator_string_has_the_pinned_hash_input_layout() {
    use sha2::{Digest, Sha512};

    let string = generator_string(PRS, CI, &sid()).expect("generator string");
    assert_eq!(string.len(), 170);
    assert_eq!(&string[..18], b"\x08CPace255\x08Password");
    assert_eq!(string[18], 109);
    assert!(string[19..128].iter().all(|byte| *byte == 0));
    assert_eq!(
        &string[128..],
        [&[24], CI, &[16], sid().as_slice()].concat()
    );
    assert_eq!(
        &Sha512::digest(string)[..32],
        bytes("03998087bdb1a2617bbe25ef5a7c18cd4f84f902328701790958755ee4aed1d3")
    );
}

#[test]
fn official_low_order_inputs_are_rejected() {
    let scalar = bytes32("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
    let invalid = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    for point in invalid {
        assert_eq!(
            x25519_scalar_mult_vfy(scalar, bytes32(point)),
            Err(CpaceError::InvalidPeerPoint),
            "accepted low-order point {point}"
        );
    }
}

#[test]
fn official_noncanonical_and_valid_inputs_match() {
    let scalar = bytes32("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff");
    let vectors = [
        (
            "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
        ),
        (
            "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
        ),
        (
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
        ),
        (
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
            "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
        ),
        (
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
            "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
        ),
    ];

    for (point, product) in vectors {
        assert_eq!(
            x25519_scalar_mult_vfy(scalar, bytes32(point)).expect("valid point"),
            bytes32(product)
        );
    }
}

#[test]
fn transcript_context_is_bound_and_secret_state_is_redacted() {
    let sid = sid();
    let scalar = [7; 32];
    let (state, message) = start(
        Side::Allocator,
        b"dice-derived secret",
        b"context",
        &sid,
        b"application data",
        scalar,
    )
    .expect("start");
    let debug = format!("{state:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("dice-derived secret"));
    assert!(!debug.contains(&hex::encode(scalar)));

    assert_eq!(
        finish(state, &message),
        Err(CpaceError::SameSide),
        "same-side transcripts must not complete"
    );
}
