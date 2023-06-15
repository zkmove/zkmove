// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::call_trace_table::{
    IMM_BORROW_GLOBAL_GENERIC_AS_FIELD, MUT_BORROW_GLOBAL_GENERIC_AS_FIELD,
};
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::error;
use movelang::word::ValueHeader;
use movelang::word::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct BorrowGlobal<const MUTABLE: bool, const GENERIC: bool, F: FieldExt> {
    account_address: Cell<F>,
    word: Vec<Cell<F>>,
    word_mask: Vec<Cell<F>>,
    word_addr_ext_0: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    type_cells: Option<GenericTypeGadget<F>>,
}

impl<const MUTABLE: bool, const GENERIC: bool, F: FieldExt> InstructionGadget<F>
    for BorrowGlobal<MUTABLE, GENERIC, F>
{
    const NAME: &'static str = match (MUTABLE, GENERIC) {
        (true, true) => "MUT_BORROW_GLOBAL_GENERIC",
        (true, false) => "MUT_BORROW_GLOBAL",
        (false, true) => "IMM_BORROW_GLOBAL_GENERIC",
        (false, false) => "IMM_BORROW_GLOBAL",
    };

    const OPCODE: Opcode = match (MUTABLE, GENERIC) {
        (true, true) => Opcode::MutBorrowGlobalGeneric,
        (true, false) => Opcode::MutBorrowGlobal,
        (false, true) => Opcode::ImmBorrowGlobalGeneric,
        (false, false) => Opcode::ImmBorrowGlobal,
    };
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num_expr = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + word_elem_num_expr.clone();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", pc_expr),
            ("stack size", stack_size_expr),
            ("frame index", frame_index_expr),
            ("gc", gc_expr),
            ("module index", module_index),
            ("function index", func_index),
        ]);

        let account_address_expr = self.account_address.expression.clone(); // account_address
        let sd_index_expr = cells.auxiliary_1.expression.clone(); //sd_index

        // pop account_address
        cb.add_lookup(
            "borrow global(stack pop)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "borrow global(stack pop value)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                account_address_expr.clone(),
            ),
        );

        for (i, _) in self.word.iter().enumerate() {
            cb.condition(1.expr() - self.word_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "borrow_global(global read)",
                    RWLookup::global_read(
                        cells.gc.expression.clone() + (i as u64 + 2).expr(),
                        account_address_expr.clone(),
                        self.word[i].expression.clone(),
                        if GENERIC {
                            sd_index_expr.clone() * 2u64.pow(16).expr()
                        } else {
                            sd_index_expr.clone()
                        },
                        self.word_addr_ext_0[i].expression.clone(),
                    ),
                );
            });
        }

        for (i, item) in self.ref_val.iter().enumerate() {
            cb.add_lookup(
                "borrow_global(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + word_elem_num_expr.clone()
                        + (i as u64 + 2).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // ref_val[1] == account_address && ref_val[2] == sd_index;
        cb.add_constraint(
            "borrow_locals_ref_eq_0",
            self.ref_val[0].expression.clone() - ValueHeader::default_for_ref_val().expr(),
        );
        cb.add_constraint(
            "borrow_global_ref_eq_1",
            self.ref_val[1].expression.clone() - account_address_expr,
        );
        cb.add_constraint(
            "borrow_global_ref_eq_2",
            self.ref_val[2].expression.clone()
                - if GENERIC {
                    sd_index_expr.clone() * 2u64.pow(16).expr()
                } else {
                    sd_index_expr.clone()
                },
        );
        cb.add_constraint("borrow_locals_ref_eq_3", self.ref_val[3].expression.clone());

        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, sd_index_expr);
        if GENERIC {
            self.type_cells.as_ref().unwrap().configure(cells, cb);
        }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // get account_address
        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        self.account_address
            .assign(region, offset, op.value().value())?;

        cells.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .expect("sd_index should not be None")
                .value(),
        )?;

        let word_elem_num = Word::get_word_element_num(region, offset, step, cells)?;
        let global_value = Word {
            word: self.word.clone(),
            word_mask: self.word_mask.clone(),
            word_addr_ext_0: self.word_addr_ext_0.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &global_value,
            step.gc + 2,
            word_elem_num,
        )?;

        let ref_val = RefVal {
            ref_val: self.ref_val.clone(),
            ref_val_mask: self.ref_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &ref_val,
            step.gc + 2 + word_elem_num,
            LEN_OF_REFERENCE_VALUE,
        )?;
        if GENERIC {
            cells.auxiliary_2.assign(
                region,
                offset,
                step.auxiliary_2
                    .as_ref()
                    .expect("callee_node id should not be none")
                    .value(),
            )?;
            cells.auxiliary_4.assign(
                region,
                offset,
                step.auxiliary_4
                    .as_ref()
                    .expect("caller_pc should not be none")
                    .value(),
            )?;
            if let Some(ExecutionData::StorageOp(data)) = &step.data {
                self.type_cells
                    .as_ref()
                    .unwrap()
                    .assign(region, offset, data.clone())?;
            } else {
                error!("expect execution data in {} gadget", Self::NAME);
                return Err(Error::Synthesis);
            }
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let account_address = cb.alloc_cell();
        let word = cb.alloc_n_cells(word_cap);
        let word_mask = cb.alloc_n_cells(word_cap);
        let word_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let ref_val = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let ref_val_mask = cb.alloc_n_cells(LEN_OF_REFERENCE_VALUE);
        let type_cells = if GENERIC {
            let instantiation_index = cb.curr.cells.auxiliary_1.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let callee_id = cb.curr.cells.auxiliary_2.expr();
            let callee_module = 0.expr();
            let callee_function = (if MUTABLE {
                MUT_BORROW_GLOBAL_GENERIC_AS_FIELD
            } else {
                IMM_BORROW_GLOBAL_GENERIC_AS_FIELD
            } as u64)
                .expr();

            Some(GenericTypeGadget::construct(
                Self::NAME,
                cb,
                caller_callin_pc,
                callee_id,
                callee_module,
                callee_function,
                instantiation_index,
            ))
        } else {
            None
        };
        Self {
            account_address,
            word,
            word_mask,
            word_addr_ext_0,
            ref_val,
            ref_val_mask,
            type_cells,
        }
    }
}
