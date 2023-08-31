// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct Not<F: FieldExt> {
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Not<F> {
    const NAME: &'static str = "NOT";

    const OPCODE: Opcode = Opcode::Not;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let input_hi = self.value_a_hi.expression.clone();
        let input_lo = self.value_a_lo.expression.clone();
        let out_hi = self.value_c_hi.expression.clone();
        let out_lo = self.value_c_lo.expression.clone();

        // out is 0 or 1
        let constraint = out_lo.clone() * (1.expr() - out_lo.clone());
        cb.add_constraint("out value is bool", constraint);
        cb.add_constraint("out_hi is zero", out_hi);

        // TODO. need to optimize
        let constraint = (input_hi + input_lo) * out_lo;
        cb.add_constraint("Not", constraint);

        let unary_op = UnaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb);
        UnaryOp::lookup_unary_op(cb, cells, &unary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Not, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let unary_op = UnaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, &unary_op)
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a_hi = cb.alloc_cell();
        let value_a_lo = cb.alloc_cell();
        let value_c_hi = cb.alloc_cell();
        let value_c_lo = cb.alloc_cell();

        Self {
            value_a_hi,
            value_a_lo,
            value_c_hi,
            value_c_lo,
        }
    }
}
