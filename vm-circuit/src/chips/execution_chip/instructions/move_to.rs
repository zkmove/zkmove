// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::common::reference_value_gadget::RefValGadget;
use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
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
use movelang::value_ext::LEN_OF_REFERENCE_VALUE;

#[derive(Clone, Debug)]
pub struct MoveTo<const GENERIC: bool, F: FieldExt> {
    value: ValueGadget<F>,
    signer_ref: RefValGadget<F>,
    account_address: Cell<F>,
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
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 2u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let flattened_value_len = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2u64.expr() * flattened_value_len.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr();
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

        self.value.configure(cb, flattened_value_len.clone());
        self.signer_ref.configure(cb);
        let global_address = self.account_address.expression.clone();

        let sd_index = cells.auxiliary_1.expression.clone();

        for (i, _) in self.value.cells.word.iter().enumerate() {
            let (read_stack, write_global) = RWLookup::move_to_global(
                cells.gc.expression.clone() + (i as u64).expr(),
                cells.stack_size.expression.clone(),
                global_address.clone(),
                if GENERIC {
                    sd_index.clone() * 2u64.pow(16).expr()
                } else {
                    sd_index.clone()
                },
                self.value.cells.word_addr_ext[i].expression.clone(),
                self.value.cells.word[i].expression.clone(),
                flattened_value_len.clone(),
                (LEN_OF_REFERENCE_VALUE as u64).expr(),
            );
            cb.condition(
                1u64.expr() - self.value.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup("move_to(stack read)", read_stack);
                    cb.add_lookup("move_to(global write)", write_global);
                },
            );
        }

        // lookup the signer reference is popped
        for (i, item) in self.signer_ref.cells.as_inner().iter().enumerate() {
            cb.add_lookup(
                "move_to(signer stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + flattened_value_len.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1u64.expr(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // todo: constrain the relationship between signer_ref and account_address

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
        let _sd_idx =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.value
            .assign(region, offset, rw_operations, step.gc, flattened_value_len)?;
        self.signer_ref
            .assign(region, offset, rw_operations, step.gc + flattened_value_len)?;

        // global account address
        let op = rw_operations
            .0
            .get(step.gc + flattened_value_len + LEN_OF_REFERENCE_VALUE)
            .ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        self.account_address
            .assign(region, offset, Some(op.account_address().value()))?;

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
        let value = ValueGadget::construct(cb);
        let signer_ref = RefValGadget::construct(cb);
        let account_address = cb.alloc_cell();

        let type_cells = if GENERIC {
            let instantiation_index = cb.curr.cells.auxiliary_1.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let callee_id = cb.curr.cells.auxiliary_2.expr();
            let callee_module = 0u64.expr();
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
            value,
            signer_ref,
            account_address,
            type_cells,
        }
    }
}
