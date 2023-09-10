// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::common::simple_value_gadget::SimpleValueGadget;
use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::call_trace_table::MOVE_FROM_GENERIC_AS_FIELD;
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::error;
use movelang::value_ext::{ValueHeader, LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};

#[derive(Clone, Debug)]
pub struct MoveFrom<const GENERIC: bool, F: FieldExt> {
    account_address: SimpleValueGadget<F>,
    global_value: ValueGadget<F>,

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
        let flattened_value_len = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + flattened_value_len.clone() * 3.expr() // two for global read resource, one for stack push value
            + (LEN_OF_SIMPLE_VALUE as u64).expr(); // stack pop account_address
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

        self.account_address.configure(cb);
        self.global_value.configure(cb);

        let account_address_expr = self.account_address.cells.value().expression.clone();
        let sd_index_expr = cells.auxiliary_1.expression.clone();

        // pop account_address
        cb.add_lookup(
            "move_from(stack pop value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "move_from(stack pop value)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + (LOWER_FIELD_OFFSET as u64).expr(),
                cells.stack_size.expression.clone(),
                2.expr(),
                account_address_expr.clone(),
            ),
        );

        for (i, _) in self.global_value.cells.word.iter().enumerate() {
            let (read_global, write_invalid_to_global, write_stack) =
                RWLookup::move_from_global_to_stack(
                    cells.gc.expression.clone() + ((i + LEN_OF_SIMPLE_VALUE) as u64).expr(),
                    account_address_expr.clone(),
                    if GENERIC {
                        sd_index_expr.clone() * 2u64.pow(16).expr()
                    } else {
                        sd_index_expr.clone()
                    },
                    cells.stack_size.expression.clone(),
                    self.global_value.cells.word_addr_ext[i].expression.clone(),
                    self.global_value.cells.word[i].expression.clone(),
                    flattened_value_len.clone(),
                );
            cb.condition(
                1.expr() - self.global_value.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup("move_from(global read)", read_global);
                    cb.add_lookup("move_from(invalid)", write_invalid_to_global);
                    cb.add_lookup("move_from(stack write)", write_stack);
                },
            );
        }

        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, sd_index_expr);
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
        let _flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.account_address
            .assign(region, offset, rw_operations, step.gc)?;
        self.global_value
            .assign(region, offset, rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;

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
        // alloc cell
        let account_address = SimpleValueGadget::construct(cb);
        let global_value = ValueGadget::construct(cb);

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
            account_address,
            global_value,
            type_cells,
        }
    }
}
