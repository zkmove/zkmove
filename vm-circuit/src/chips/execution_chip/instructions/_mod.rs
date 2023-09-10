// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    get_u256_from_op, get_u256_from_value, BinaryOp, LookupBytecode,
};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::mul_add_words::MulAddWordsGadget;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value_ext::LEN_OF_SIMPLE_VALUE;

#[derive(Clone, Debug)]
pub struct Mod<F: FieldExt> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_b_hi: Cell<F>,
    value_b_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Mod<F> {
    const NAME: &'static str = "Mod";

    const OPCODE: Opcode = Opcode::Mod;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        self.muladd_words_gadget.configure(cb);

        // alloc cell
        let binary_op = BinaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Mod, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        BinaryOp::assign_binary_op_with_auxiliary(
            region,
            offset,
            step,
            rw_operations,
            cells,
            &binary_op,
        )?;

        // muladd_gadget assign
        let divisor = get_u256_from_op(rw_operations, step.gc)?;
        let divident = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let reminder = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let v = step
            .auxiliary_1
            .as_ref()
            .ok_or_else(|| {
                error!("auxiliary_1 is None");
                Error::Synthesis
            })?
            .clone();
        let quotient = get_u256_from_value(v)?;
        let words = [divisor, quotient, reminder, divident];
        self.muladd_words_gadget.assign(region, offset, words)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let muladd_words_gadget = MulAddWordsGadget::<F>::construct(cb);
        let value_a_hi = cb.alloc_cell();
        let value_a_lo = cb.alloc_cell();
        let value_b_hi = cb.alloc_cell();
        let value_b_lo = cb.alloc_cell();
        let value_c_hi = cb.alloc_cell();
        let value_c_lo = cb.alloc_cell();

        Self {
            muladd_words_gadget,
            value_a_hi,
            value_a_lo,
            value_b_hi,
            value_b_lo,
            value_c_hi,
            value_c_lo,
        }
    }
}
