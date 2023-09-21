// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{ArithOverflow, BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::base_constraint_builder::BaseConstraintBuilder;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::execution_chip::utils::pow_of_two_expr;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct Add<F: FieldExt> {
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    out: WordCells<F>,
    bytes: Vec<Cell<F>>,
    carry_lo: Cell<F>,
    // carry_hi: Cell<F>, // overflow
}

impl<F: FieldExt> InstructionGadget<F> for Add<F> {
    const NAME: &'static str = "ADD";

    const OPCODE: Opcode = Opcode::Add;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let mut bcb = BaseConstraintBuilder::default();
        //Add
        let (lhs_hi, lhs_lo) = self.value_a.expr();
        let (rhs_hi, rhs_lo) = self.value_b.expr();
        let (out_hi, out_lo) = self.out.expr();
        let carry_lo = self.carry_lo.expression.clone();
        bcb.require_equal(
            "left operand(lo) + right operand(lo) == out_lo + carry_lo ⋅ 2^128",
            lhs_lo + rhs_lo,
            out_lo.clone() + carry_lo.clone() * pow_of_two_expr(128),
        );
        bcb.require_equal(
            "left operand(hi) + right operand(hi) + carry_lo == out_hi",
            lhs_hi + rhs_hi + carry_lo.clone(),
            out_hi,
        );
        // carry_lo in set of (0, 1)
        bcb.require_in_set(
            "carry_lo in set",
            carry_lo,
            (0..2).map(|idx| idx.expr()).collect(),
        );
        // Todo. need to constraint on carry_lo furthermore?
        // carry_lo = if a > c {1.expr()} else 0.expr();

        ArithOverflow::constrain_range_check(cb, cells, self.bytes.clone(), out_lo);
        ArithOverflow::lookup_arith_op(cb, cells, cells.auxiliary_1.expression.clone());

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.out.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Add, 0.expr());

        cb.add_constraints(bcb.constraints);
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
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.out.clone(),
        };
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        // get out_lo
        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_SIMPLE_VALUE * 2 + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let v = op.value();
        ArithOverflow::assign_num_of_bytes(
            region,
            offset,
            step,
            cells,
            self.bytes.clone(),
            v.clone(),
        )?;
        let out_lo = v.value().ok_or(Error::Synthesis)?;

        // get value_a_lo
        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_SIMPLE_VALUE + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let value_a_lo = op.value().value().ok_or(Error::Synthesis)?;

        let carry_lo = if out_lo < value_a_lo {
            F::one()
        } else {
            F::zero()
        };
        self.carry_lo.assign(region, offset, Some(carry_lo))?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let out = WordCells::<F>::construct(cb);
        let bytes = cb.alloc_n_cells(BYTES_NUM);
        let carry_lo = cb.alloc_cell();

        Self {
            value_a,
            value_b,
            out,
            bytes,
            carry_lo,
        }
    }
}
