// Copyright (c) zkMove Authors

pub use move_core_types::u256;
pub use move_core_types::u256::U256;
pub use move_core_types::value::MoveValue;
use move_core_types::value::MoveValue::*;
pub use move_vm_types::loaded_data::runtime_types::Type as MoveValueType;
use types::Field;

/// Takes U256, converts to bytes32 (big endian) and
/// returns (bytes[16..], bytes[..16]) represented as big endian numbers in the prime field
pub fn convert_u256_to_u128_pair(input: &U256) -> [u128; 2] {
    let bytes = input.to_le_bytes();
    let mut data = [0u8; 16];
    data.copy_from_slice(&bytes[16..]);
    let v1 = u128::from_le_bytes(data);
    data.copy_from_slice(&bytes[..16]);
    let v2 = u128::from_le_bytes(data);
    [v1, v2]
}

/// Takes U256, converts to bytes32 (big endian) and
/// returns (bytes[16..], bytes[..16]) represented as big endian numbers in the prime field
pub fn convert_u256_to_field<F: Field>(input: &U256) -> [F; 2] {
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
pub fn convert_u256_to_fe<F: Field>(input: U256) -> F {
    let val = input % modulus::<F>();
    let bytes = val.to_le_bytes();
    // repr is in little endian
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    F::from_repr(repr).unwrap()
}

//TODO: put all utilities of U256 into one place
pub fn pair_u128_to_u256(lo: u128, hi: u128) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&lo.to_le_bytes());
    bytes[16..].copy_from_slice(&hi.to_le_bytes());
    U256::from_le_bytes(&bytes)
}
pub fn split_u256_to_u128(input: U256) -> (u128, u128) {
    let bytes = input.to_le_bytes();
    let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
    (lo, hi)
}

pub fn decode_u128_pair_to_u256(fe: &[u128]) -> U256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&fe[0].to_le_bytes());
    bytes[..16].copy_from_slice(&fe[1].to_le_bytes());
    U256::from_le_bytes(&bytes)
}

pub fn decode_field_to_u256<F: Field>(fe: &[F]) -> U256 {
    assert_eq!(fe.len(), 2);
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&fe[0].to_repr().as_ref()[..16]);
    bytes[..16].copy_from_slice(&fe[1].to_repr().as_ref()[..16]);
    U256::from_le_bytes(&bytes)
}

/// Returns modulus of [`PrimeField`] as [`U256`].
pub fn modulus<F: Field>() -> U256 {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice((-F::ONE).to_repr().as_ref());
    U256::from_le_bytes(&bytes) + U256::one()
}

pub fn convert_to_u128(value: MoveValue) -> u128 {
    match value {
        U8(u) => u as u128,
        U16(u) => u as u128,
        U32(u) => u as u128,
        U64(u) => u as u128,
        U128(u) => u,
        Bool(b) => {
            if b {
                1u128
            } else {
                0u128
            }
        }
        _ => unimplemented!(),
    }
}

pub fn convert_to_field<F: Field>(value: MoveValue) -> F {
    match value {
        U8(u) => F::from_u128(u as u128),
        U16(u) => F::from_u128(u as u128),
        U32(u) => F::from_u128(u as u128),
        U64(u) => F::from_u128(u as u128),
        U128(u) => F::from_u128(u),
        Bool(b) => {
            if b {
                F::ONE
            } else {
                F::ZERO
            }
        }
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::convert_to_field;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::ff::PrimeField;
    use logger::debug;
    use move_core_types::u256::U256;
    // use move_core_types::value::MoveValue::*;

    #[test]
    fn test_conversion() {
        assert_eq!(convert_to_field::<Fr>(U8(0u8)), Fr::zero());
        assert_eq!(convert_to_field::<Fr>(U16(0u16)), Fr::zero());
        assert_eq!(convert_to_field::<Fr>(U32(0u32)), Fr::zero());
        assert_eq!(convert_to_field::<Fr>(U64(0u64)), Fr::zero());
        assert_eq!(convert_to_field::<Fr>(U128(0u128)), Fr::zero());
        assert_eq!(convert_to_field::<Fr>(Bool(false)), Fr::zero());

        assert_eq!(convert_to_field::<Fr>(U8(1u8)), Fr::one());
        assert_eq!(convert_to_field::<Fr>(U16(1u16)), Fr::one());
        assert_eq!(convert_to_field::<Fr>(U32(1u32)), Fr::one());
        assert_eq!(convert_to_field::<Fr>(U64(1u64)), Fr::one());
        assert_eq!(convert_to_field::<Fr>(U128(1u128)), Fr::one());
        assert_eq!(convert_to_field::<Fr>(Bool(true)), Fr::one());

        assert_eq!(convert_to_field::<Fr>(U8(0x11u8)), Fr::from_u128(0x11u128));
        assert_eq!(
            convert_to_field::<Fr>(U16(0x1111u16)),
            Fr::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fr>(U32(0x1111u32)),
            Fr::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fr>(U64(0x1111u64)),
            Fr::from_u128(0x1111u128)
        );
        assert_eq!(
            convert_to_field::<Fr>(U128(0x1111111111u128)),
            Fr::from_u128(0x1111111111u128)
        );
        assert_eq!(
            convert_to_field::<Fr>(U128(0x1111111111111111u128)),
            Fr::from_u128(0x1111111111111111u128)
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
        let c = convert_u256_to_field::<Fr>(&b);
        let d = convert_u256_to_fe::<Fr>(b);
        let e = decode_field_to_u256(&c);
        assert_eq!(b, e);

        debug!("u256 value is: {:x}", b);
        debug!("multiple field value is: {:?}", c);
        debug!("single field val is: {:?}", d);
        debug!(" {:x}", e);
    }
}
