// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
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
pub struct Mod<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Mod<F> {
    const NAME: &'static str = "Mod";

    const OPCODE: Opcode = Opcode::Mod;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.opcode_selector([Self::OPCODE]);

        let lhs = self.value_a.expression.clone();
        let rhs = self.value_b.expression.clone();
        let remainder = self.value_c.expression.clone();
        let quotient = cells.auxiliary_1.expression.clone();
        let constraint = cond.clone() * (lhs - rhs * quotient - remainder);
        cb.add_constraint("Mod", constraint);

        // alloc cell
        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cells, cb, cond.clone());
        BinaryOp::lookup_binary_op(cells, &binary_op, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Mod,
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
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::assign_binary_op_with_auxiliary(
            region,
            offset,
            step,
            rw_operations,
            cells,
            &binary_op,
        )
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
