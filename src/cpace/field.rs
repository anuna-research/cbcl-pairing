//! Minimal Curve25519 field wrapper for the revision-21 Elligator2 map.

use fiat_crypto::curve25519_64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_square,
    fiat_25519_from_bytes, fiat_25519_loose_field_element as Loose, fiat_25519_opp,
    fiat_25519_relax, fiat_25519_sub, fiat_25519_tight_field_element as Tight, fiat_25519_to_bytes,
};

const ONE: FieldElement = FieldElement(Tight([1, 0, 0, 0, 0]));
const CURVE_A: FieldElement = FieldElement(Tight([486_662, 0, 0, 0, 0]));
const CURVE_A_OVER_TWO: FieldElement = FieldElement(Tight([243_331, 0, 0, 0, 0]));

const P_MINUS_TWO: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const P_MINUS_ONE_OVER_TWO: [u8; 32] = [
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
];

#[derive(Clone, Copy)]
struct FieldElement(Tight);

impl FieldElement {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut result = Tight([0; 5]);
        fiat_25519_from_bytes(&mut result, &bytes);
        Self(result)
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut result = [0_u8; 32];
        fiat_25519_to_bytes(&mut result, &self.0);
        result
    }

    fn add(self, rhs: Self) -> Self {
        let mut loose = Loose([0; 5]);
        let mut result = Tight([0; 5]);
        fiat_25519_add(&mut loose, &self.0, &rhs.0);
        fiat_25519_carry(&mut result, &loose);
        Self(result)
    }

    fn sub(self, rhs: Self) -> Self {
        let mut loose = Loose([0; 5]);
        let mut result = Tight([0; 5]);
        fiat_25519_sub(&mut loose, &self.0, &rhs.0);
        fiat_25519_carry(&mut result, &loose);
        Self(result)
    }

    fn neg(self) -> Self {
        let mut loose = Loose([0; 5]);
        let mut result = Tight([0; 5]);
        fiat_25519_opp(&mut loose, &self.0);
        fiat_25519_carry(&mut result, &loose);
        Self(result)
    }

    fn mul(self, rhs: Self) -> Self {
        let mut left = Loose([0; 5]);
        let mut right = Loose([0; 5]);
        let mut result = Tight([0; 5]);
        fiat_25519_relax(&mut left, &self.0);
        fiat_25519_relax(&mut right, &rhs.0);
        fiat_25519_carry_mul(&mut result, &left, &right);
        Self(result)
    }

    fn square(self) -> Self {
        let mut loose = Loose([0; 5]);
        let mut result = Tight([0; 5]);
        fiat_25519_relax(&mut loose, &self.0);
        fiat_25519_carry_square(&mut result, &loose);
        Self(result)
    }

    fn pow(self, exponent: &[u8; 32]) -> Self {
        let mut result = ONE;
        for byte in exponent.iter().rev() {
            for bit in (0..8).rev() {
                result = result.square();
                if byte & (1 << bit) != 0 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    fn invert(self) -> Self {
        self.pow(&P_MINUS_TWO)
    }
}

/// Map a decoded 255-bit field element to the Curve25519 Montgomery
/// u-coordinate specified by RFC 9380 section 6.7.1 and CPace draft-21.
pub(super) fn elligator2_curve25519(mut representative: [u8; 32]) -> [u8; 32] {
    representative[31] &= 0x7f;
    let r = FieldElement::from_bytes(representative);
    let denominator = ONE.add(ONE.add(ONE).mul(r.square()));
    let v = CURVE_A.neg().mul(denominator.invert());
    let curve_equation = v.mul(v.square().add(CURVE_A.mul(v)).add(ONE));
    let epsilon = curve_equation.pow(&P_MINUS_ONE_OVER_TWO);
    epsilon
        .mul(v)
        .sub(ONE.sub(epsilon).mul(CURVE_A_OVER_TWO))
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::{FieldElement, CURVE_A, ONE, P_MINUS_ONE_OVER_TWO};

    #[test]
    fn generated_field_wrapper_roundtrips_and_inverts() {
        let mut five = [0_u8; 32];
        five[0] = 5;
        let five = FieldElement::from_bytes(five);
        assert_eq!(five.to_bytes()[0], 5);
        assert_eq!(five.mul(five).to_bytes()[0], 25);

        let product = five.mul(five.invert()).to_bytes();
        assert_eq!(product[0], 1);
        assert!(product[1..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn official_generator_field_intermediates_match() {
        let representative: [u8; 32] =
            hex::decode("03998087bdb1a2617bbe25ef5a7c18cd4f84f902328701790958755ee4aed153")
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        let r = FieldElement::from_bytes(representative);
        let denominator = ONE.add(ONE.add(ONE).mul(r.square()));
        assert_eq!(
            hex::encode(denominator.to_bytes()),
            "89ec42417baf1a1cd8c5f89d304a316641b8423bc64dacecc07f61bd5131d71c"
        );
        assert_eq!(
            hex::encode(denominator.invert().to_bytes()),
            "2be27e9a7a7f96ab2be442e88a1c778a844deb7580ee97464885640b996c347e"
        );
        let v = CURVE_A.neg().mul(denominator.invert());
        assert_eq!(
            hex::encode(v.to_bytes()),
            "1747022be095d769cd5d16d605d64142aef6daed587d6022182ceb49d0fa5840"
        );
        let equation = v.mul(v.square().add(CURVE_A.mul(v)).add(ONE));
        assert_eq!(
            hex::encode(equation.to_bytes()),
            "83ae58c2419f1073f679decace00dbc3e24f1ad237a6dd7174e44e953bd31a6e"
        );
        assert_eq!(
            hex::encode(equation.pow(&P_MINUS_ONE_OVER_TWO).to_bytes()),
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        );
    }
}
