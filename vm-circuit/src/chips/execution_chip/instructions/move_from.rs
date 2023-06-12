// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::call_trace_table::MOVE_FROM_GENERIC_AS_FIELD;
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::error;

#[derive(Clone, Debug)]
pub struct MoveFrom<const GENERIC: bool, F: FieldExt> {
    value_a: Cell<F>,
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,

    type_cells: Option<GenericTypeGadget<F>>,
}

impl<const GENERIC: bool, F: FieldExt> InstructionGadget<F> for MoveFrom<GENERIC, F> {
    const NAME: &'static str = if GENERIC {
        "MOVE_FROM_GENERIC"
    } else {
        "MOVE_FROM"
    };

    const OPCODE: Opcode = if GENERIC {
        Opcode::MoveFromGeneric
    } else {
        Opcode::MoveFrom
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + word_elem_num.clone() * 3.expr() // two for global read resource, one for stack push value
            + 1.expr(); // stack pop account_address
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
        let account_address_expr = self.value_a.expression.clone();
        let sd_index = cells.auxiliary_1.expression.clone();
        cb.add_lookup(
            "move_from(stack pop)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                account_address_expr.clone(),
            ),
        );

        for (i, _) in self.word_a.iter().enumerate() {
            let (read_global, write_invalid_to_global, write_stack) =
                RWLookup::move_from_global_to_stack(
                    cells.gc.expression.clone() + (i as u64 + 1).expr(),
                    account_address_expr.clone(),
                    if GENERIC {
                        sd_index.clone() * 2u64.pow(16).expr()
                    } else {
                        sd_index.clone()
                    },
                    cells.stack_size.expression.clone(),
                    self.word_a_addr_ext_0[i].expression.clone(),
                    self.word_a_addr_ext_1[i].expression.clone(),
                    self.word_a[i].expression.clone(),
                    word_elem_num.clone(),
                );
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                cb.add_lookup("move_from(global read)", read_global);
                cb.add_lookup("move_from(invalid)", write_invalid_to_global);
                cb.add_lookup("move_from(stack write)", write_stack);
            });
        }

        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, sd_index);
        if let Some(g) = &self.type_cells {
            g.configure(cells, cb);
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
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);

        // account address
        self.value_a.assign(region, offset, op.value().value())?;

        // resource structs
        let word_element_num = Word::get_word_element_num(region, offset, step, cells)?;
        let word = Word {
            word: self.word_a.clone(),
            word_mask: self.word_a_mask.clone(),
            word_addr_ext_0: self.word_a_addr_ext_0.clone(),
            word_addr_ext_1: self.word_a_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &word,
            step.gc + 1,
            word_element_num,
        )?;
        cells.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .expect("sd_index should not be none")
                .value(),
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
        let value_a = cb.alloc_cell();
        let word_a = cb.alloc_n_cells(word_cap);
        let word_a_mask = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_1 = cb.alloc_n_cells(word_cap);

        let type_cells = if GENERIC {
            let instantiation_index = cb.curr.cells.auxiliary_1.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let callee_id = cb.curr.cells.auxiliary_2.expr();
            let callee_module = 0.expr();
            let callee_function = (MOVE_FROM_GENERIC_AS_FIELD as u64).expr();

            let type_cells = GenericTypeGadget::construct(
                Self::NAME,
                cb,
                caller_callin_pc,
                callee_id,
                callee_module,
                callee_function,
                instantiation_index,
            );
            Some(type_cells)
        } else {
            None
        };
        Self {
            value_a,
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
            type_cells,
        }
    }
}
