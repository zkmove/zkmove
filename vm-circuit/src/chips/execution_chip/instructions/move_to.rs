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
use crate::witness::call_trace_table::MOVE_TO_GENERIC_AS_FIELD;
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::error;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct MoveTo<const GENERIC: bool, F: FieldExt> {
    value_a: Cell<F>,
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,
    type_cells: Option<GenericTypeGadget<F>>,
}

impl<const GENERIC: bool, F: FieldExt> InstructionGadget<F> for MoveTo<GENERIC, F> {
    const NAME: &'static str = if GENERIC {
        "MOVE_TO_GENERIC"
    } else {
        "MOVE_TO"
    };

    const OPCODE: Opcode = if GENERIC {
        Opcode::MoveToGeneric
    } else {
        Opcode::MoveTo
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 2.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * word_elem_num
            + depth_of_addr_path_expr.clone();
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
        let global_address = self.value_a.expression.clone();
        let sd_index = cells.auxiliary_1.expression.clone();
        let word_elem_num = cells.auxiliary_3.expression.clone();

        for (i, _) in self.word_a.iter().enumerate() {
            let (read_stack, write_global) = RWLookup::move_to_global(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone(),
                global_address.clone(),
                if GENERIC {
                    sd_index.clone() * 2u64.pow(16).expr()
                } else {
                    sd_index.clone()
                },
                self.word_a_addr_ext_0[i].expression.clone(),
                self.word_a_addr_ext_1[i].expression.clone(),
                self.word_a[i].expression.clone(),
                word_elem_num.clone(),
                depth_of_addr_path_expr.clone(),
            );
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                cb.add_lookup("move_to(stack read)", read_stack);
                cb.add_lookup("move_to(global write)", write_global);
            });
        }

        // lookup the signer reference is popped
        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            // for i in 0..DEPTH_OF_ADDRESS_PATH {
            cb.add_lookup(
                "move_to(signer stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + word_elem_num.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
            );
        }

        // todo: constrain the relationship between value_b (signer reference) and value_c (address)

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
        // word is resource on stack
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
            step.gc,
            word_element_num,
        )?;

        // assign the signer reference
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
            step.gc + word_element_num,
            DEPTH_OF_ADDRESS_PATH,
        )?;

        // value c is the global address
        let op = rw_operations
            .0
            .get(step.gc + word_element_num + DEPTH_OF_ADDRESS_PATH)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        self.value_a
            .assign(region, offset, Some(op.account_address().value()))?;
        cells.auxiliary_1.assign(
            region,
            offset,
            step.auxiliary_1
                .as_ref()
                .expect("sd_index id should not be none")
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
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let type_cells = if GENERIC {
            let instantiation_index = cb.curr.cells.auxiliary_1.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let callee_id = cb.curr.cells.auxiliary_2.expr();
            let callee_module = 0.expr();
            let callee_function = (MOVE_TO_GENERIC_AS_FIELD as u64).expr();

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
            ref_val,
            ref_val_mask,
            type_cells,
        }
    }
}
