use error::VmResult;

use movelang::account_address::AccountAddress;
use movelang::value::{
    AddressPath, GlobalLocation, GlobalResourceDefIndex, LocatedValue, SimpleValue, Value,
    ValueLocation,
};
use movelang::value_ext::LocatedFlattenedValue;
use vm_circuit::witness::rw_operations::{GlobalOp, RWOperation, RW};

pub fn emit_global_op(
    address_path: AddressPath,
    value: SimpleValue,
    rw: RW,
    rw_operations: &mut Vec<RWOperation>,
) {
    let op = GlobalOp {
        address: AccountAddress::new(
            *address_path
                .0
                .first()
                .expect("account address should not be None"),
        ),
        sd_index: *address_path.0.get(1).expect("sd_index should not be None") as usize,
        address_ext: address_path.addr_ext(),
        value: Some(value),
        rw,
        gc: rw_operations.len(),
    };
    rw_operations.push(RWOperation::GlobalOp(op));
}

#[allow(clippy::type_complexity)]
pub fn emit_global_ops(
    flattened_value: LocatedFlattenedValue,
    rw: RW,
    rw_operations: &mut Vec<RWOperation>,
) {
    for (address_path, val) in flattened_value.0 {
        emit_global_op(address_path, val, rw, rw_operations);
    }
}
pub fn emit_ops_for_global_value(
    addr: AccountAddress,
    sd_index: GlobalResourceDefIndex,
    resource_value: Value,
    rw: RW,
    write_invalid: bool,
    rw_operations: &mut Vec<RWOperation>,
) -> VmResult<usize> {
    let value_addr = GlobalLocation {
        address: addr,
        sd_index,
    };
    let flattened_value: LocatedFlattenedValue =
        LocatedValue(ValueLocation::Global(value_addr), &resource_value).into();
    let flattened_value_len = flattened_value.0.len();
    for (address_path, val) in flattened_value.0.clone() {
        let op = GlobalOp {
            address: addr,
            sd_index: sd_index.to_u128() as usize,
            address_ext: address_path.addr_ext(),
            value: Some(val),
            rw,
            gc: rw_operations.len(),
        };
        rw_operations.push(RWOperation::GlobalOp(op));
    }
    // if this is move_from, we need to write an invalid back.
    if write_invalid {
        for (address_path, _) in flattened_value.0 {
            let op = GlobalOp {
                address: addr,
                sd_index: sd_index.to_u128() as usize,
                address_ext: address_path.addr_ext(),
                value: None,
                rw: RW::WRITE,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::GlobalOp(op));
        }
    }
    Ok(flattened_value_len)
}
