// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::generic_gadget::GenericTypeGadget;
use crate::chips::execution_chip::instructions::common::reference_value_gadget::RefValGadget;
use crate::chips::execution_chip::instructions::common::simple_value_gadget::SimpleValueGadget;
use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::call_trace_table::{
    IMM_BORROW_GLOBAL_GENERIC_AS_FIELD, MUT_BORROW_GLOBAL_GENERIC_AS_FIELD,
};
use crate::witness::execution_steps::{ExecutionData, ExecutionStep};
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use logger::error;
use movelang::value_ext::LEN_OF_REFERENCE_VALUE;
use movelang::value_ext::{ValueHeader, LEN_OF_SIMPLE_VALUE};
use types::Field;

#[derive(Clone, Debug)]
pub struct BorrowGlobal<const MUTABLE: bool, const GENERIC: bool, F: Field> {
    account_address: SimpleValueGadget<F>,
    value: ValueGadget<F>,
    ref_val: RefValGadget<F>,
    type_cells: Option<GenericTypeGadget<F>>,
}

impl<const MUTABLE: bool, const GENERIC: bool, F: Field> InstructionGadget<F>
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
        // for instruction Mut(Imm)BorrowGlobal, there are 3 steps here:
        // 1. read account_address from stack. [gc, LEN_OF_SIMPLE_VALUE]
        // 2. read global data. [gc + LEN_OF_SIMPLE_VALUE, word_elem_num]
        // 3. write reference to element into stack.
        // [gc + LEN_OF_SIMPLE_VALUE + word_elem_num, LEN_OF_REFERENCE_VALUE]

        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_elem_num_expr = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + (LEN_OF_SIMPLE_VALUE as u64).expr()
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

        self.account_address.configure(cb);
        self.value.configure(cb, word_elem_num_expr.clone());
        self.ref_val.configure(cb);

        let account_address_expr = self.account_address.cells.value().expression.clone();
        let sd_index_expr = cells.auxiliary_1.expression.clone();

        // pop account_address
        self.account_address.lookup_stack_pop(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );

        for (i, _) in self.value.cells.word.iter().enumerate() {
            cb.condition(
                1u64.expr() - self.value.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup(
                        "borrow_global(global read)",
                        RWLookup::global_read(
                            cells.gc.expression.clone()
                                + (LEN_OF_SIMPLE_VALUE as u64).expr()
                                + (i as u64).expr(),
                            account_address_expr.clone(),
                            self.value.cells.word[i].expression.clone(),
                            if GENERIC {
                                sd_index_expr.clone() * 2u64.pow(16).expr()
                            } else {
                                sd_index_expr.clone()
                            },
                            self.value.cells.word_addr_ext[i].expression.clone(),
                        ),
                    );
                },
            );
        }

        for (i, item) in self.ref_val.cells.as_inner().iter().enumerate() {
            cb.add_lookup(
                "borrow_global(stack push)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + word_elem_num_expr.clone()
                        + (LEN_OF_SIMPLE_VALUE as u64).expr()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1u64.expr(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // ref_val[1] == account_address && ref_val[2] == sd_index;
        cb.add_constraint(
            "borrow_locals_ref_eq_0",
            self.ref_val.cells[0].expression.clone() - ValueHeader::default_for_ref_val().expr(),
        );
        cb.add_constraint(
            "borrow_global_ref_eq_1",
            self.ref_val.cells[1].expression.clone() - account_address_expr,
        );
        cb.add_constraint(
            "borrow_global_ref_eq_2",
            self.ref_val.cells[2].expression.clone()
                - if GENERIC {
                    sd_index_expr.clone() * 2u64.pow(16).expr()
                } else {
                    sd_index_expr.clone()
                },
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_3",
            self.ref_val.cells[3].expression.clone(),
        );

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
        let _sd_idx =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.account_address
            .assign(region, offset, rw_operations, step.gc)?;
        self.value.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE,
            flattened_value_len,
        )?;
        self.ref_val.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE + flattened_value_len,
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
        // alloc cell
        let account_address = SimpleValueGadget::construct(cb);
        let value = ValueGadget::construct(cb);
        let ref_val = RefValGadget::construct(cb);
        let type_cells = if GENERIC {
            let instantiation_index = cb.curr.cells.auxiliary_1.expr();
            let caller_callin_pc = cb.curr.cells.auxiliary_4.expr();
            let callee_id = cb.curr.cells.auxiliary_2.expr();
            let callee_module = 0u64.expr();
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
            value,
            ref_val,
            type_cells,
        }
    }
}
