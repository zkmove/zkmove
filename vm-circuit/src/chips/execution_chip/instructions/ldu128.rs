// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Cell;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct LdU128<F: FieldExt> {
    value_a: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdU128<F> {
    const NAME: &'static str = "LDU128";

    const OPCODE: Opcode = Opcode::LdU128;
    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        //LdU128
        let cond = cells.conditions[Opcode::LdU128.index()].expression.clone();

        // alloc cell
        let value_a = cb.query_cell();

        LoadOp::constrain_ld_op(cells, cb, cond.clone());
        LoadOp::lookup_ld_op(cells, &value_a, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::LdU128,
            value_a.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );

        Self { value_a }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let value_a = &self.value_a;
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.query_cell();

        Self { value_a }
    }
}
