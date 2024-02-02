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
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::utility::U256;
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
use types::Field;

use super::common::get_field_from_op;
use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct Mul<F: Field> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: Field> InstructionGadget<F> for Mul<F> {
    const NAME: &'static str = "MUL";

    const OPCODE: Opcode = Opcode::Mul;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // equal to MulAddWordsGadget cells.
        let expr = MulAddWordsOp {
            a_hi: self.value_a.hi.expression.clone(),
            a_lo: self.value_a.lo.expression.clone(),
            b_hi: self.value_b.hi.expression.clone(),
            b_lo: self.value_b.lo.expression.clone(),
            c_hi: 0u64.expr(),
            c_lo: 0u64.expr(),
            d_hi: self.value_c.hi.expression.clone(),
            d_lo: self.value_c.lo.expression.clone(),
        };
        self.muladd_words_gadget.configure(cb, expr);

        let out = self.value_c.lo.expression.clone();
        ArithOverflow::constrain_range_check(cb, cells, self.bytes.clone(), out);
        ArithOverflow::lookup_arith_op(cb, cells, cells.auxiliary_1.expression.clone());

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Mul, 0u64.expr());
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
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        // result into bytes representation
        let v = get_field_from_op(
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE * 2 + LOWER_FIELD_OFFSET,
        )?;
        ArithOverflow::assign_num_of_bytes(
            region,
            offset,
            step,
            cells,
            self.bytes.clone(),
            Some(v),
        )?;

        // muladd_gadget assign
        let b = get_u256_from_op::<F>(rw_operations, step.gc)?;
        let a = get_u256_from_op::<F>(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let res = get_u256_from_op::<F>(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let words = [a, b, U256::zero(), res];
        self.muladd_words_gadget.assign(region, offset, words)?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let muladd_words_gadget = MulAddWordsGadget::<F>::construct(cb);
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            muladd_words_gadget,
            value_a,
            value_b,
            value_c,
            bytes,
        }
    }
}
