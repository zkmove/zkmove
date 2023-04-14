// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value::DEPTH_OF_ADDRESS_PATH;
use std::marker::PhantomData;

pub struct BorrowLoc<const MUTABLE: bool, F: FieldExt> {
    _word_a: [Cell<F>; WORD_CAPACITY],
    _word_a_mask: [Cell<F>; WORD_CAPACITY],
    _word_a_addr_ext_0: [Cell<F>; WORD_CAPACITY],
    _word_a_addr_ext_1: [Cell<F>; WORD_CAPACITY],
    _ref_val: [Cell<F>; DEPTH_OF_ADDRESS_PATH],
    _marker: PhantomData<F>,
}

impl<const MUTABLE: bool, F: FieldExt> Instructions<F> for BorrowLoc<MUTABLE, F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let opcode = if MUTABLE {
            Opcode::MutBorrowLoc
        } else {
            Opcode::ImmBorrowLoc
        };

        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + word_element_num.clone()
            + (DEPTH_OF_ADDRESS_PATH as u64).expr();
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

        for i in 0..WORD_CAPACITY {
            let read = RWLookup::locals_ref(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.frame_index.expression.clone(),
                cells.locals_index.expression.clone(),
                cells.word_a_addr_ext_0[i].expression.clone(),
                cells.word_a_addr_ext_1[i].expression.clone(),
                cells.word_a[i].expression.clone(),
            );

            lookups.rw_lookups.push((
                read,
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
        }

        for i in 0..DEPTH_OF_ADDRESS_PATH {
            lookups.rw_lookups.push((
                RWLookup::stack_push(
                    cells.gc.expression.clone() + word_element_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    cells.ref_val[i].expression.clone(),
                ),
                cond.clone(),
            ));
        }

        // ref_val[0] == frame_index && ref_val[1] == locals_index;
        let mut constraint = cond.clone()
            * (cells.ref_val[0].expression.clone() - cells.frame_index.expression.clone());
        constraints.push(("borrow_locals_ref_eq", constraint));
        constraint = cond.clone()
            * (cells.ref_val[1].expression.clone() - cells.locals_index.expression.clone());
        constraints.push(("borrow_locals_ref_eq", constraint));

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            cells.locals_index.expression.clone(),
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
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + word_element_num,
            DEPTH_OF_ADDRESS_PATH,
        )?;
        Ok(())
    }
}
