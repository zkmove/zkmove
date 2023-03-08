use error::VmResult;
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::file_format::StructDefinitionIndex;
use movelang::account_address::AccountAddress;
use movelang::value::{AddressPath, GlobalLocation, SimpleValue, Value, ValueLocation};
use vm_circuit::witness::rw_operations::{GlobalOp, RWOperation, RW};

pub fn emit_global_ops_for_word<F: FieldExt>(
    word: Vec<(AddressPath<F>, SimpleValue<F>)>,
    addr: AccountAddress<F>,
    sd_index: StructDefinitionIndex,
    rw: RW,
    rw_operations: &mut Vec<RWOperation<F>>,
) {
    for (address_path, val) in word {
        let op = GlobalOp {
            address: addr,
            sd_index: sd_index.0 as usize,
            address_ext_0: *address_path
                .0
                .get(2)
                .expect("address_ext_0 should not be None"),
            address_ext_1: *address_path
                .0
                .get(3)
                .expect("address_ext_1 should not be None"),
            value: Some(val),
            rw: rw.clone(),
            gc: rw_operations.len(),
        };
        rw_operations.push(RWOperation::GlobalOp(op));
    }
}
pub fn emit_ops_for_global_value<F: FieldExt>(
    addr: AccountAddress<F>,
    sd_index: StructDefinitionIndex,
    resource_value: Value<F>,
    rw: RW,
    write_invalid: bool,
    rw_operations: &mut Vec<RWOperation<F>>,
) -> VmResult<usize> {
    let value_addr = GlobalLocation {
        address: addr,
        sd_index,
    };
    let word = resource_value.flatten(ValueLocation::Global(value_addr));
    let word_len = word.len();
    for (address_path, val) in word.clone() {
        let op = GlobalOp {
            address: addr,
            sd_index: sd_index.0 as usize,
            address_ext_0: *address_path
                .0
                .get(2)
                .expect("address_ext_0 should not be None"),
            address_ext_1: *address_path
                .0
                .get(3)
                .expect("address_ext_1 should not be None"),
            value: Some(val),
            rw: rw.clone(),
            gc: rw_operations.len(),
        };
        rw_operations.push(RWOperation::GlobalOp(op));
    }
    // if this is move_from, we need to write an invalid back.
    if write_invalid {
        for (address_path, _) in word {
            let op = GlobalOp {
                address: addr,
                sd_index: sd_index.0 as usize,
                address_ext_0: *address_path
                    .0
                    .get(2)
                    .expect("address_ext_0 should not be None"),
                address_ext_1: *address_path
                    .0
                    .get(3)
                    .expect("address_ext_1 should not be None"),
                value: None,
                rw: RW::WRITE,
                gc: rw_operations.len(),
            };
            rw_operations.push(RWOperation::GlobalOp(op));
        }
    }
    Ok(word_len)
}
