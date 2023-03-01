// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, WORD_CAPACITY};
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value::DEPTH_OF_ADDRESS_PATH;
use std::marker::PhantomData;

pub struct MoveTo<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for MoveTo<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::MoveTo.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 2.expr() * word_elem_num
            + depth_of_addr_path_expr.clone();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);
        let global_address = cells.value_c.expression.clone();
        let sd_index = cells.auxiliary_1.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();
        for i in 0..WORD_CAPACITY {
            let (read_stack, write_global) = RWLookup::move_to_global(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone(),
                global_address.clone(),
                sd_index.clone(),
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
                cells.word_a[i].expression.clone(),
                word_elem_num.clone(),
                depth_of_addr_path_expr.clone(),
            );
            lookups.rw_lookups.push((
                read_stack,
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
            lookups.rw_lookups.push((
                write_global,
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
        }

        // lookup the signer reference is popped
        for i in 0..DEPTH_OF_ADDRESS_PATH {
            lookups.rw_lookups.push((
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + word_elem_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    cells.ref_val[i].expression.clone(),
                ),
                cond.clone(),
            ));
        }

        // todo: constrain the relationship between value_b (signer reference) and value_c (address)

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::MoveTo,
            sd_index,
            &mut lookups.bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // word_a is resource on stack
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc,
            word_element_num,
        )?;

        // assign the signer reference
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + word_element_num,
        )?;

        // value c is the global address
        let op = rw_operations
            .0
            .get(step.gc + word_element_num + DEPTH_OF_ADDRESS_PATH)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells
            .value_c
            .assign(region, offset, Some(op.account_address().value()))?;
        cells
            .auxiliary_1
            .assign(region, offset, Some(F::from_u128(op.sd_index() as u128)))?;

        Ok(())
    }
}
