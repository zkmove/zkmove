// Copyright (c) zkMove Authors

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
pub use move_core_types::u256;
pub use move_core_types::u256::U256;
pub use move_core_types::value::MoveValue;
use move_core_types::value::MoveValue::*;
pub use move_vm_types::loaded_data::runtime_types::Type as MoveValueType;

/// Takes U256, converts to bytes32 (big endian) and
/// returns (bytes[16..], bytes[..16]) represented as big endian numbers in the prime field
pub fn convert_u256_to_field<F: FieldExt>(input: &U256) -> [F; 2] {
    let bytes = input.to_le_bytes();
    // repr is in little endian
    let mut repr = F::Repr::default();
    repr.as_mut()[..16].copy_from_slice(&bytes[16..]);
    let v1 = F::from_repr(repr).unwrap();
    repr.as_mut()[..16].copy_from_slice(&bytes[..16]);
    let v2 = F::from_repr(repr).unwrap();
    [v1, v2]
}

// u256 need to be converted into one filed in some case.
// F::invert can't be extended into 2 fileds.
pub fn convert_u256_to_fe<F: FieldExt>(input: U256) -> F {
    let val = input % modulus::<F>();
    let bytes = val.to_le_bytes();
    // repr is in little endian
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    F::from_repr(repr).unwrap()
}

pub fn decode_field_to_u256<F: FieldExt>(fe: &[F]) -> U256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&fe[0].to_repr().as_ref()[..16]);
    bytes[..16].copy_from_slice(&fe[1].to_repr().as_ref()[..16]);
    U256::from_le_bytes(&bytes)
}

/// Returns modulus of [`PrimeField`] as [`U256`].
pub fn modulus<F: FieldExt>() -> U256 {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice((-F::one()).to_repr().as_ref());
    U256::from_le_bytes(&bytes) + U256::one()
}

pub fn convert_to_field<F: FieldExt>(value: MoveValue) -> F {
    match value {
        U8(u) => F::from_u128(u as u128),
        U16(u) => F::from_u128(u as u128),
        U32(u) => F::from_u128(u as u128),
        U64(u) => F::from_u128(u as u128),
        U128(u) => F::from_u128(u),
        Bool(b) => {
            if b {
                F::one()
            } else {
                F::zero()
            }
        }
        _ => unimplemented!(),
    }
}

pub fn move_div(left: MoveValue, right: MoveValue) -> VmResult<MoveValue> {
    let result = match (left, right) {
        (U8(l), U8(r)) => u8::checked_div(l, r).map(U8),
        (U16(l), U16(r)) => u16::checked_div(l, r).map(U16),
        (U32(l), U32(r)) => u32::checked_div(l, r).map(U32),
        (U64(l), U64(r)) => u64::checked_div(l, r).map(U64),
        (U128(l), U128(r)) => u128::checked_div(l, r).map(U128),
        (U256(l), U256(r)) => u256::U256::checked_div(l, r).map(U256),
        (l, r) => {
            let msg = format!("can not div {:?} by {:?}", l, r);
            return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
        }
    };
    result.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
}

pub fn move_rem(left: MoveValue, right: MoveValue) -> VmResult<MoveValue> {
    let result = match (left, right) {
        (U8(l), U8(r)) => u8::checked_rem(l, r).map(U8),
        (U16(l), U16(r)) => u16::checked_rem(l, r).map(U16),
        (U32(l), U32(r)) => u32::checked_rem(l, r).map(U32),
        (U64(l), U64(r)) => u64::checked_rem(l, r).map(U64),
        (U128(l), U128(r)) => u128::checked_rem(l, r).map(U128),
        (U256(l), U256(r)) => u256::U256::checked_rem(l, r).map(U256),
        (l, r) => {
            let msg = format!("can not div {:?} by {:?}", l, r);
            return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
        }
    };
    result.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::convert_to_field;
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::halo2curves::pasta::Fp;
    use logger::debug;
    use move_core_types::u256::U256;
    // use move_core_types::value::MoveValue::*;

    #[test]
    fn test_conversion() {
        assert_eq!(convert_to_field::<Fp>(U8(0u8)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U16(0u16)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U32(0u32)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U64(0u64)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U128(0u128)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(Bool(false)), Fp::zero());

        assert_eq!(convert_to_field::<Fp>(U8(1u8)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U16(1u16)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U32(1u32)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U64(1u64)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U128(1u128)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(Bool(true)), Fp::one());

        assert_eq!(convert_to_field::<Fp>(U8(0x11u8)), Fp::from_u128(0x11u128));
        assert_eq!(
            convert_to_field::<Fp>(U16(0x1111u16)),
            Fp::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fp>(U32(0x1111u32)),
            Fp::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fp>(U64(0x1111u64)),
            Fp::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fp>(U128(0x1111111111u128)),
            Fp::from_u128(0x1111111111u128)
        );
        assert_eq!(
            convert_to_field::<Fp>(U128(0x1111111111111111u128)),
            Fp::from_u128(0x1111111111111111u128)
        );
    }

    #[test]
    fn test_u256_field_conversion() {
        logger::init_for_test();

        // a is base field modulus
        let a = U256::from_str_radix(
            "40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
            16,
        )
        .unwrap();

        let b = a + U256::from(1234u32);
        // 2 field:
        // [0x0000000000000000000000000000000030644e72e131a029b85045b68181585d,
        //  0x000000000000000000000000000000002833e84879b9709143e1f593f00004d3]
        let c = convert_u256_to_field::<Fp>(&b);
        let d = convert_u256_to_fe::<Fp>(b);
        let e = decode_field_to_u256(&c);
        assert_eq!(b, e);

        debug!("u256 value is: {:x}", b);
        debug!("multiple field value is: {:?}", c);
        debug!("single field val is: {:?}", d);
        debug!(" {:x}", e);
        // 10 / 2 = 5 and 10 % 3 = 1
        debug!(
            "10 div 2 into {:?}",
            move_div(U256(U256::from(10u32)), U256(U256::from(2u32)))
        );
        debug!(
            "10 rem 3 into {:?}",
            move_rem(U256(U256::from(10u32)), U256(U256::from(3u32)))
        );
    }
}
