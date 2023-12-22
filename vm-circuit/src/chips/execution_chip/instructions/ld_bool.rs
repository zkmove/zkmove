// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LoadOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use types::Field;

use super::common::simple_value_gadget::SimpleValueGadget;

#[derive(Clone, Debug)]
pub struct LdBool<F: Field, const TRUE: bool> {
    value: SimpleValueGadget<F>,
}

impl<F: Field, const TRUE: bool> InstructionGadget<F> for LdBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "LDTRUE",
        false => "LDFALSE",
    };

    const OPCODE: Opcode = match TRUE {
        true => Opcode::LdTrue,
        false => Opcode::LdFalse,
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        self.value.configure(cb);

        LoadOp::constrain_ld_op(cells, cb);
        self.value.lookup_stack_push(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );
        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, 0u64.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        self.value.assign(region, offset, rw_operations, step.gc)?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value = SimpleValueGadget::construct(cb);

        Self { value }
    }
}
