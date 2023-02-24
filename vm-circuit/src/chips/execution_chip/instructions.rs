// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};

pub mod _mod;
pub mod abort;
pub mod add;
pub mod and;
pub mod bit_and;
pub mod bit_or;
pub mod borrow_global;
pub mod br_false;
pub mod br_true;
pub mod branch;
pub mod call;
pub mod castu128;
pub mod castu64;
pub mod castu8;
pub mod common;
pub mod copy_loc;
pub mod div;
pub mod eq;
pub mod exists;
pub mod freeze_ref;
pub mod ge;
pub mod gt;
pub mod imm_borrow_field;
pub mod imm_borrow_loc;
pub mod ld_false;
pub mod ld_true;
pub mod ldu128;
pub mod ldu64;
pub mod ldu8;
pub mod le;
pub mod lt;
pub mod move_from;
pub mod move_loc;
pub mod move_to;
pub mod mul;
pub mod mut_borrow_field;
pub mod mut_borrow_loc;
pub mod neq;
pub mod nop;
pub mod not;
pub mod or;
pub mod pack;
pub mod pop;
pub mod read_ref;
pub mod ret;
pub mod shl;
pub mod shr;
pub mod st_loc;
pub mod stop;
pub mod sub;
pub mod unpack;
pub mod write_ref;
pub mod xor;
pub trait Instructions<F: FieldExt> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    );

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error>;
}
