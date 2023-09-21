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

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct Or<F: FieldExt> {
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
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
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
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
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);

        Self {
            value_a,
            value_b,
            value_c,
        }
    }
}
