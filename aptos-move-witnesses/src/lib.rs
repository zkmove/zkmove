extern crate move_vm_runtime;

pub use move_vm_runtime::witnessing::{
    traced_value::{Integer, Reference, SimpleValue, ValueItem},
    BinaryIntegerOperationType, Footprint, Operation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witnesses {
    pub opcode_witnesses: Vec<Footprint>,
}
pub mod exec_state;
pub mod step_state;
pub mod utils;

pub mod witness_preprocessor;

pub mod sub_index {
    use crate::step_state::SubIndex;

    pub fn concat(mut index1: SubIndex, mut index2: SubIndex) -> SubIndex {
        while let Some(0) = index1.last() {
            index1.pop();
        }

        index1.append(&mut index2);
        index1
    }
}
