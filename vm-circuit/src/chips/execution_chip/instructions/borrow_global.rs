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

pub struct BorrowGlobal<const MUTABLE: bool, F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<const MUTABLE: bool, F: FieldExt> Instructions<F> for BorrowGlobal<MUTABLE, F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let opcode = if MUTABLE {
            Opcode::MutBorrowGlobal
        } else {
            Opcode::ImmBorrowGlobal
        };
        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let word_elem_num_expr = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone()
            + 1.expr()
            + depth_of_addr_path_expr
            + word_elem_num_expr.clone();
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

        let account_address_expr = cells.value_a.expression.clone(); // address
        let sd_index_expr = cells.auxiliary_1.expression.clone(); //sd_index
        lookups.rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                account_address_expr.clone(),
            ),
            cond.clone(),
        ));

        for i in 0..WORD_CAPACITY {
            lookups.rw_lookups.push((
                RWLookup::global_read(
                    cells.gc.expression.clone() + (i as u64 + 1).expr(),
                    account_address_expr.clone(),
                    cells.word_a[i].expression.clone(),
                    sd_index_expr.clone(),
                    cells.word_a_addr_ext_0[i].expression.clone(),
                    cells.word_a_addr_ext_1[i].expression.clone(),
                ),
                cond.clone() * (1.expr() - cells.word_a_mask[i].expression.clone()),
            ));
        }

        for i in 0..DEPTH_OF_ADDRESS_PATH {
            lookups.rw_lookups.push((
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + word_elem_num_expr.clone()
                        + (i as u64 + 1).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    cells.ref_val[i].expression.clone(),
                ),
                cond.clone(),
            ));
        }

        // ref_val[0] == account_address && ref_val[1] == sd_index;
        // Todo. account address is changed into u128 at function `address_path`
        // let mut constraint =
        //     cond.clone() * (cells.ref_val[0].expression.clone() - account_address_expr);
        // constraints.push(("borrow_global_ref_eq", constraint));
        let constraint = cond.clone() * (cells.ref_val[1].expression.clone() - sd_index_expr.clone());
        constraints.push(("borrow_global_ref_eq", constraint));

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            sd_index_expr,
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        cells.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .expect("sd_index should not be None")
                .value(),
        )?;

        let word_elem_num = Word::get_word_element_num(region, offset, step, cells)?;
        Word::assign_word_a(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1,
            word_elem_num,
        )?;

        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            cells,
            step.gc + 1 + word_elem_num,
            DEPTH_OF_ADDRESS_PATH,
        )?;
        Ok(())
    }
}
