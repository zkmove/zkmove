// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

pub mod _mod;
pub mod abort;
pub mod add;
pub mod and;
pub mod bit_and;
pub mod bit_or;
pub mod borrow_field;
pub mod borrow_global;
pub mod borrow_loc;
pub mod br_false;
pub mod br_true;
pub mod branch;
pub mod call;
pub mod call_generic;
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

pub(crate) trait InstructionGadget<F: FieldExt> {
    const NAME: &'static str;

    const OPCODE: Opcode;

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    );

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error>;

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self;
}
