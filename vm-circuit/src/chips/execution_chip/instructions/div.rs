// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    get_u256_from_op, get_u256_from_value, BinaryOp, LookupBytecode,
};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::mul_add_words::{MulAddWordsGadget, MulAddWordsOp};
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value_ext::LEN_OF_SIMPLE_VALUE;
use types::Field;

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct Div<F: Field> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
}

impl<F: Field> InstructionGadget<F> for Div<F> {
    const NAME: &'static str = "DIV";

    const OPCODE: Opcode = Opcode::Div;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // equal to MulAddWordsGadget cells.
        let expr = MulAddWordsOp {
            a_hi: self.value_b.hi.expression.clone(),
            a_lo: self.value_b.lo.expression.clone(),
            b_hi: self.value_c.hi.expression.clone(),
            b_lo: self.value_c.lo.expression.clone(),
            c_hi: cells.auxiliary_2.expression.clone(),
            c_lo: cells.auxiliary_1.expression.clone(),
            d_hi: self.value_a.hi.expression.clone(),
            d_lo: self.value_a.lo.expression.clone(),
        };
        self.muladd_words_gadget.configure(cb, expr);

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Div, 0u64.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
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
        let divisor = get_u256_from_op::<F>(rw_operations, step.gc)?;
        let divident = get_u256_from_op::<F>(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let quotient = get_u256_from_op::<F>(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let v = step
            .auxiliary_1
            .as_ref()
            .ok_or_else(|| {
                error!("auxiliary_1 is None");
                Error::Synthesis
            })?
            .clone();
        let reminder = get_u256_from_value(v)?;
        let words = [divisor, quotient, reminder, divident];
        self.muladd_words_gadget.assign(region, offset, words)?;

        Ok(())
    }
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let muladd_words_gadget = MulAddWordsGadget::<F>::construct(cb);
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);

        Self {
            muladd_words_gadget,
            value_a,
            value_b,
            value_c,
        }
    }
}
