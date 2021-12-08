// Copyright (c) zkMove Authors

use error::{RuntimeError, StatusCode, VmResult};
use halo2::arithmetic::FieldExt;
pub use move_core_types::value::MoveValue;
use move_core_types::value::MoveValue::{Bool, U128, U64, U8};
pub use move_vm_types::loaded_data::runtime_types::Type as MoveValueType;

pub fn convert_to_field<F: FieldExt>(value: MoveValue) -> F {
    match value {
        U8(u) => F::from_u64(u as u64),
        U64(u) => F::from_u64(u),
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
        (U64(l), U64(r)) => u64::checked_div(l, r).map(U64),
        (U128(l), U128(r)) => u128::checked_div(l, r).map(U128),
        (l, r) => {
            let msg = format!("can not div {:?} by {:?}", l, r);
            return Err(RuntimeError::new(StatusCode::TypeMissMatch).with_message(msg));
        }
    };
    result.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
}

pub fn move_rem(left: MoveValue, right: MoveValue) -> VmResult<MoveValue> {
    let result = match (left, right) {
        (U8(l), U8(r)) => u8::checked_rem(l, r).map(U8),
        (U64(l), U64(r)) => u64::checked_rem(l, r).map(U64),
        (U128(l), U128(r)) => u128::checked_rem(l, r).map(U128),
        (l, r) => {
            let msg = format!("can not div {:?} by {:?}", l, r);
            return Err(RuntimeError::new(StatusCode::TypeMissMatch).with_message(msg));
        }
    };
    result.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
}

#[cfg(test)]
mod tests {
    use crate::value::convert_to_field;
    use halo2::arithmetic::FieldExt;
    use halo2::pasta::Fp;
    use move_core_types::value::MoveValue::{Bool, U128, U64, U8};

    #[test]
    fn test_conversion() {
        assert_eq!(convert_to_field::<Fp>(U8(0u8)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U64(0u64)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(U128(0u128)), Fp::zero());
        assert_eq!(convert_to_field::<Fp>(Bool(false)), Fp::zero());

        assert_eq!(convert_to_field::<Fp>(U8(1u8)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U64(1u64)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(U128(1u128)), Fp::one());
        assert_eq!(convert_to_field::<Fp>(Bool(true)), Fp::one());

        assert_eq!(convert_to_field::<Fp>(U8(0x11u8)), Fp::from_u64(0x11u64));
        assert_eq!(
            convert_to_field::<Fp>(U64(0x1111u64)),
            Fp::from_u64(0x1111u64)
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
}
