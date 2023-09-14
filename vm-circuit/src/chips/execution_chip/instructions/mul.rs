// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    get_u256_from_op, ArithOverflow, BinaryOp, LookupBytecode,
};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::mul_add_words::{MulAddWordsGadget, MulAddWordsOp};
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::utility::U256;
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
// use super::common::get_u256_from_op;

#[derive(Clone, Debug)]
pub struct Mul<F: FieldExt> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_b_hi: Cell<F>,
    value_b_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Mul<F> {
    const NAME: &'static str = "MUL";

    const OPCODE: Opcode = Opcode::Mul;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // equal to MulAddWordsGadget cells.
        let expr = MulAddWordsOp {
            a_hi: self.value_a_hi.expression.clone(),
            a_lo: self.value_a_lo.expression.clone(),
            b_hi: self.value_b_hi.expression.clone(),
            b_lo: self.value_b_lo.expression.clone(),
            c_hi: 0.expr(),
            c_lo: 0.expr(),
            d_hi: self.value_c_hi.expression.clone(),
            d_lo: self.value_c_lo.expression.clone(),
        };
        self.muladd_words_gadget.configure(cb, expr);

        let out = self.value_c_lo.expression.clone();
        ArithOverflow::constrain_range_check(cb, cells, self.bytes.clone(), out);
        ArithOverflow::lookup_arith_op(cb, cells, cells.auxiliary_1.expression.clone());

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
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Mul, 0.expr());
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
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        // result into bytes representation
        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_SIMPLE_VALUE * 2 + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let value = op.value();
        ArithOverflow::assign_num_of_bytes(region, offset, step, cells, self.bytes.clone(), value)?;

        // muladd_gadget assign
        let b = get_u256_from_op(rw_operations, step.gc)?;
        let a = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let res = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let words = [a, b, U256::zero(), res];
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
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            muladd_words_gadget,
            value_a_hi,
            value_a_lo,
            value_b_hi,
            value_b_lo,
            value_c_hi,
            value_c_lo,
            bytes,
        }
    }
}
