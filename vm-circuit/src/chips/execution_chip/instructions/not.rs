// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
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
    value_a: Cell<F>,
    value_c: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Not<F> {
    const NAME: &'static str = "NOT";

    const OPCODE: Opcode = Opcode::Not;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.opcode_selector([Self::OPCODE]);

        let x = self.value_a.expression.clone();
        let out = self.value_c.expression.clone();

        // out is 0 or 1
        let constraint = cond.clone() * out.clone() * (1.expr() - out.clone());
        cb.add_constraint("out value is bool", constraint);

        // 1 - x = out
        let constraint = cond.clone() * (1.expr() - x - out);
        cb.add_constraint("Not", constraint);

        let unary_op = UnaryOp {
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb, cond.clone());
        UnaryOp::lookup_unary_op(cells, &unary_op, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Not,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
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
        let value_a = cb.alloc_cell();
        let value_c = cb.alloc_cell();

        Self { value_a, value_c }
    }
}
