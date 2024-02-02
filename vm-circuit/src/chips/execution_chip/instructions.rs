// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use types::Field;
pub mod _mod;
pub mod abort;
pub mod add;
pub mod and;
pub mod bit_and;
pub mod bit_or;
pub mod borrow_field;
pub mod borrow_global;
pub mod borrow_loc;
pub mod br_bool;
pub mod branch;
pub mod call;
pub mod castint;
pub mod castu256;
pub mod common;
pub mod copy_loc;
pub mod div;
pub mod equality;
pub mod exists;
pub mod freeze_ref;
pub mod ge;
pub mod gt;
pub mod ld_bool;
pub mod ld_const;
pub mod ldint;
pub mod ldu256;
pub mod le;
pub mod lt;
pub mod move_from;
pub mod move_loc;
pub mod move_to;
pub mod mul;
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
pub mod vec_borrow;
pub mod vec_len;
pub mod vec_pack;
pub mod vec_pop_back;
pub mod vec_push_back;
pub mod vec_swap;
pub mod vec_unpack;
pub mod write_ref;
pub mod xor;
pub(crate) trait InstructionGadget<F: Field> {
    const NAME: &'static str;

    const OPCODE: Opcode;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>);

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error>;

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self;
}
