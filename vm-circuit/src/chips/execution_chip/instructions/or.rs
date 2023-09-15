// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

use super::common::word_gadget::WordCell;

#[derive(Clone, Debug)]
pub struct Or<F: FieldExt> {
    value_a: WordCell<F>,
    value_b: WordCell<F>,
    value_c: WordCell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Or<F> {
    const NAME: &'static str = "OR";

    const OPCODE: Opcode = Opcode::Or;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let lhs = self.value_a.lo.expression.clone();
        let rhs = self.value_b.lo.expression.clone();
        let out = self.value_c.lo.expression.clone();

        // out is 0 or 1
        let constraint = out.clone() * (1.expr() - out.clone());
        cb.add_constraint("out value is bool", constraint);

        let constraint = (1.expr() - lhs) * (1.expr() - rhs) - (1.expr() - out);
        cb.add_constraint("Or", constraint);

        let binary_op = BinaryOp {
            value_a_hi: self.value_a.hi.clone(),
            value_a_lo: self.value_a.lo.clone(),
            value_b_hi: self.value_b.hi.clone(),
            value_b_lo: self.value_b.lo.clone(),
            value_c_hi: self.value_c.hi.clone(),
            value_c_lo: self.value_c.lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Or, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a_hi: self.value_a.hi.clone(),
            value_a_lo: self.value_a.lo.clone(),
            value_b_hi: self.value_b.hi.clone(),
            value_b_lo: self.value_b.lo.clone(),
            value_c_hi: self.value_c.hi.clone(),
            value_c_lo: self.value_c.lo.clone(),
        };
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCell::<F>::construct(cb);
        let value_b = WordCell::<F>::construct(cb);
        let value_c = WordCell::<F>::construct(cb);

        Self {
            value_a,
            value_b,
            value_c,
        }
    }
}
