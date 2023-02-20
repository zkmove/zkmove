use error::VmResult;
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::file_format::StructDefinitionIndex;
use movelang::account_address::AccountAddress;
use movelang::value::{Value, ValueAddress};
use vm_circuit::witness::rw_operations::{GlobalOp, RWOperation, RW};

pub fn emit_globals_ops_for_word<F: FieldExt>(
    addr: AccountAddress<F>,
    sd_index: StructDefinitionIndex,
    resource_value: Value<F>,
    rw: RW,
    rw_operations: &mut Vec<RWOperation<F>>,
) -> VmResult<usize> {
    let value_addr = ValueAddress::Global(addr, sd_index);
    let addressed_value = resource_value.update_address(value_addr.clone());
    let word = addressed_value.flatten(value_addr)?;
    let word_len = word.len();
    for (address_path, val) in word {
        let locals_op = GlobalOp {
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
            value: val,
            rw: rw.clone(),
            gc: rw_operations.len(),
        };
        rw_operations.push(RWOperation::GlobalOp(locals_op));
    }
    Ok(word_len)
}
