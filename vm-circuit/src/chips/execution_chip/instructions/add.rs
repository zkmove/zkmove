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

#[derive(Clone, Debug)]
pub struct Add<F: FieldExt> {
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_b_hi: Cell<F>,
    value_b_lo: Cell<F>,
    out_hi: Cell<F>,
    out_lo: Cell<F>,
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
        let lhs = self.value_a_lo.expression.clone();
        let rhs = self.value_b_lo.expression.clone();
        let out_lo = self.out_lo.expression.clone();
        let carry_lo = self.carry_lo.expression.clone();
        bcb.require_equal(
            "left operand(lo) + right operand(lo) == out_lo + carry_lo ⋅ 2^128",
            lhs + rhs,
            out_lo.clone() + carry_lo.clone() * pow_of_two_expr(128),
        );
        let lhs = self.value_a_hi.expression.clone();
        let rhs = self.value_b_hi.expression.clone();
        let out_hi = self.out_hi.expression.clone();
        bcb.require_equal(
            "left operand(hi) + right operand(hi) + carry_lo == out_hi",
            lhs + rhs + carry_lo.clone(),
            out_hi,
        );
        // carry_lo in set of (0, 1)
        bcb.require_in_set(
            "carry_lo in set",
            carry_lo,
            (0..2).map(|idx| idx.expr()).collect(),
        );

        ArithOverflow::constrain_range_check(cb, cells, self.bytes.clone(), out_lo);
        ArithOverflow::lookup_arith_op(cb, cells, cells.auxiliary_1.expression.clone());

        let binary_op = BinaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.out_hi.clone(),
            value_c_lo: self.out_lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Add, 0.expr());
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
            value_c_hi: self.out_hi.clone(),
            value_c_lo: self.out_lo.clone(),
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
            .get(step.gc + LOWER_FIELD_OFFSET)
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
        let value_a_hi = cb.alloc_cell();
        let value_a_lo = cb.alloc_cell();
        let value_b_hi = cb.alloc_cell();
        let value_b_lo = cb.alloc_cell();
        let out_hi = cb.alloc_cell();
        let out_lo = cb.alloc_cell();
        let bytes = cb.alloc_n_cells(BYTES_NUM);
        let carry_lo = cb.alloc_cell();

        Self {
            value_a_hi,
            value_a_lo,
            value_b_hi,
            value_b_lo,
            out_hi,
            out_lo,
            bytes,
            carry_lo,
        }
    }
}
