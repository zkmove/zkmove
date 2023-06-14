// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct And<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for And<F> {
    const NAME: &'static str = "AND";

    const OPCODE: Opcode = Opcode::And;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let lhs = self.value_a.expression.clone();
        let rhs = self.value_b.expression.clone();
        let out = self.value_c.expression.clone();

        // out is 0 or 1
        let constraint = out.clone() * (1.expr() - out.clone());
        cb.add_constraint("out value is bool", constraint);

        let constraint = lhs * rhs - out;
        cb.add_constraint("And", constraint);

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::And, 0.expr());
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
        let value_a = cb.alloc_cell();
        let value_b = cb.alloc_cell();
        let value_c = cb.alloc_cell();

        Self {
            value_a,
            value_b,
            value_c,
        }
    }
}
