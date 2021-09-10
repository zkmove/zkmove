use error::{RuntimeError, StatusCode, VmResult};
pub use move_core_types::value::MoveValue;
use move_core_types::value::MoveValue::{U128, U64, U8};
pub use move_vm_types::loaded_data::runtime_types::Type as MoveValueType;

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
