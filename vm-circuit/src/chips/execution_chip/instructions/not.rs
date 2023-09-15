// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
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
pub struct Not<F: FieldExt> {
    value_a: WordCell<F>,
    value_c: WordCell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Not<F> {
    const NAME: &'static str = "NOT";

    const OPCODE: Opcode = Opcode::Not;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let (input_hi, input_lo) = self.value_a.expr();
        let (out_hi, out_lo) = self.value_c.expr();

        // out is 0 or 1
        let constraint = out_lo.clone() * (1.expr() - out_lo.clone());
        cb.add_constraint("out value is bool", constraint);
        cb.add_constraint("out_hi is zero", out_hi);

        // TODO. need to optimize
        let constraint = (input_hi + input_lo) * out_lo;
        cb.add_constraint("Not", constraint);

        let unary_op = UnaryOp {
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
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
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, &unary_op)
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCell::<F>::construct(cb);
        let value_c = WordCell::<F>::construct(cb);

        Self { value_a, value_c }
    }
}
