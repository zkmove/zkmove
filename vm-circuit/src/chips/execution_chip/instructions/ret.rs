// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::LookupBytecode;
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{
    call_lookup_table::CallLookup, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Expr, SubInvert};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::function_calls::EntryType;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Ret<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Ret<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::Ret.index()].expression.clone();
        let call_index = cells.call_index.expression.clone();
        let inverse = cells.auxiliary_1.expression.clone();

        // constrain the inverse, if call_index != 0, call_index * inverse(call_index) == 1
        let call_index_expr =
            call_index.clone() * (call_index.clone() * inverse.clone() - 1.expr());

        // if call_index == 0, the next step will be 'Nop' or 'Stop', we have
        // call_index * inverse(call_index) != 1
        // next_pc == pc
        let pc_expr = (call_index.clone() * inverse.clone() - 1.expr())
            * (cells.next_pc.expression.clone() - cells.pc.expression.clone());

        // gc should not change
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone();
        constraints.append(&mut vec![
            ("call_index", cond.clone() * call_index_expr),
            ("pc", cond.clone() * pc_expr),
            ("gc", cond.clone() * gc_expr),
        ]);

        // if call_index != 0, the next step will be a normal bytecode,
        // (type_, module_index, function_index, pc, next_module_index, next_function_index, next_pc)
        // must be in calls table.
        lookups.call_lookups.push((
            CallLookup {
                type_: (EntryType::RET as u64).expr(),
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                next_module_index: cells.next_module_index.expression.clone(),
                next_function_index: cells.next_function_index.expression.clone(),
                next_pc: cells.next_pc.expression.clone(),
            },
            call_index * inverse * cond.clone(), // only take effect when call_index != 0
        ));

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Ret,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        _rw_table: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        cells
            .auxiliary_1
            .assign(region, offset, (step.call_index as usize).sub_invert(0))?;

        Ok(())
    }
}
