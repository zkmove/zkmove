// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::constant_lookup_table::ConstantLookup;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::error;

#[derive(Clone, Debug)]
pub struct LdConst<F: FieldExt> {
    const_value: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for LdConst<F> {
    const NAME: &'static str = "LdConst";

    const OPCODE: Opcode = Opcode::LdConst;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let const_index = cells.auxiliary_1.expr();

        LoadOp::constrain_ld_op(cells, cb);
        LoadOp::lookup_ld_op(cb, cells, &self.const_value);
        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, const_index.clone());
        cb.add_lookup(
            "constant lookup",
            ConstantLookup {
                module_index: cells.module_index.expr(),
                constant_index: const_index,
                value: self.const_value.expr(),
            },
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cell: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        self.const_value
            .assign(region, offset, op.value().value())?;
        cell.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .ok_or_else(|| {
                    error!("auxiliary_1 is None");
                    Error::Synthesis
                })?
                .value(),
        )?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let const_value = cb.alloc_cell();

        Self { const_value }
    }
}
