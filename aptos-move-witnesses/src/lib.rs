#![feature(slice_as_chunks)]
extern crate move_core_types;

pub use move_vm_runtime::witnessing::{
    traced_value::{Integer, Reference, SimpleValue, ValueItem},
    BinaryIntegerOperationType, EntryCall, Footprint, Operation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witnesses {
    pub opcode_witnesses: Vec<Footprint>,
}
pub mod exec_state;
pub mod static_info;
pub mod step_state;
pub mod types;
pub mod utils;
pub mod witness_preprocessor;
