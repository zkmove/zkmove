// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct LdTrue<F: FieldExt> {
    value_a: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdTrue<F> {
    const NAME: &'static str = "LDTRUE";

    const OPCODE: Opcode = Opcode::LdTrue;

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //LdTrue
        let cond = cells.conditions[Opcode::LdTrue.index()].expression.clone();

        LoadOp::constrain_ld_op(cells, cb, cond.clone());
        LoadOp::lookup_ld_op(cells, &self.value_a, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::LdTrue,
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        self.value_a.assign(region, offset, op.value().value())?;
        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.alloc_cell();

        Self { value_a }
    }
}
