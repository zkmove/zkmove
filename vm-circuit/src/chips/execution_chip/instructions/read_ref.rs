// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::reference_value_gadget::RefValGadget;
use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use movelang::value_ext::ValueHeader;
use movelang::value_ext::LEN_OF_REFERENCE_VALUE;
use types::Field;

#[derive(Clone, Debug)]
pub struct ReadRef<F: Field> {
    ref_val: RefValGadget<F>,
    value_a: ValueGadget<F>,
    value_b: ValueGadget<F>,
}

impl<F: Field> InstructionGadget<F> for ReadRef<F> {
    const NAME: &'static str = "READREF";

    const OPCODE: Opcode = Opcode::ReadRef;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction readref, there are 3 pipeline stages here:
        // 1. read reference from stack. [gc, LEN_OF_REFERENCE_VALUE]
        // 2. read value from lobals or global. [gc+LEN_OF_REFERENCE_VALUE, flattened_value_len]
        // 3. store value into stack. [gc+LEN_OF_REFERENCE_VALUE+flattened_value_len, flattened_value_len]

        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let flattened_value_len = cells.auxiliary_3.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + 2u64.expr() * flattened_value_len.clone();
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

        self.ref_val.configure(cb);
        self.value_a.configure(cb, flattened_value_len.clone());
        self.value_b.configure(cb, flattened_value_len.clone());

        for (i, item) in self.ref_val.cells.as_inner().iter().enumerate() {
            cb.add_lookup(
                "read_ref(stack pop)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        let is_global = cells.auxiliary_5.expression.clone();
        for (i, item) in self.value_b.cells.word.iter().enumerate() {
            cb.condition(
                1u64.expr() - self.value_a.cells.word_mask[i].expression.clone(),
                |cb| {
                    // locals read or global read
                    let read = RWLookup::locals_read(
                        cells.gc.expression.clone()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        cells.auxiliary_2.expression.clone(), // frame_index
                        cells.locals_index.expression.clone(), // index
                        self.value_a.cells.word_addr_ext[i].expression.clone(),
                        item.expression.clone(),
                    );
                    // locals read
                    cb.condition(1u64.expr() - is_global.clone(), |cb| {
                        cb.add_lookup("read_ref(locals read)", read);
                    });

                    let read = RWLookup::global_read(
                        cells.gc.expression.clone()
                            + (LEN_OF_REFERENCE_VALUE as u64).expr()
                            + (i as u64).expr(),
                        cells.auxiliary_2.expression.clone(), // account_address
                        item.expression.clone(),
                        cells.auxiliary_4.expression.clone(), //sd_index
                        self.value_a.cells.word_addr_ext[i].expression.clone(),
                    );
                    // global read
                    cb.condition(is_global.clone(), |cb| {
                        cb.add_lookup("read_ref(global read)", read);
                    });
                },
            );

            // stack write
            let write = RWLookup::stack_push(
                cells.gc.expression.clone()
                    + (LEN_OF_REFERENCE_VALUE as u64).expr()
                    + flattened_value_len.clone()
                    + (i as u64).expr(),
                cells.stack_size.expression.clone() - 1u64.expr(),
                self.value_b.cells.word_addr_ext[i].expression.clone(),
                item.expression.clone(),
            );
            cb.condition(
                1u64.expr() - self.value_b.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup("read_ref(stack push)", write);
                },
            );
        }

        // ref_val[0] equals to ref value header
        let constraint =
            self.ref_val.cells[0].expression.clone() - ValueHeader::default_for_ref_val().expr();
        cb.add_constraint("read_ref_eq_0", constraint);

        // ref_val[1] equals to frame_index(Locals) or account_address(Global)
        let constraint =
            self.ref_val.cells[1].expression.clone() - cells.auxiliary_2.expression.clone();
        cb.add_constraint("read_ref_eq_1", constraint);

        // ref_val[2] equel to local_index(Locals) or sd_index(Global)
        let constraint = (1u64.expr() - is_global.clone())
            * (self.ref_val.cells[2].expression.clone() - cells.locals_index.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);
        let constraint = is_global
            * (self.ref_val.cells[2].expression.clone() - cells.auxiliary_4.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);

        // ref_val[3] equal to value_a_addr_ext
        let constraint = self.ref_val.cells[3].expression.clone()
            - self.value_a.cells.word_addr_ext[0].expression.clone();
        cb.add_constraint("read_ref_eq_3", constraint);

        LookupBytecode::lookup_bytecode(cb, cells, Opcode::ReadRef, 0u64.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_operations: &RWOperations,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.ref_val
            .assign(region, offset, rw_operations, step.gc)?;

        self.value_a.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_REFERENCE_VALUE,
            flattened_value_len,
        )?;

        self.value_b.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_REFERENCE_VALUE + flattened_value_len,
            flattened_value_len,
        )?;

        let is_global =
            Word::assign_step_value(region, offset, &step.auxiliary_5, &cells.auxiliary_5)?;
        if is_global == F::ZERO {
            // assign the frame_index of the frame we refer to
            let _aux_value =
                Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
        } else {
            // assign the account address to auxiliary_2
            let _address =
                Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
            // assign the sd_index to auxiliary_4
            let _sd_index =
                Word::assign_step_value(region, offset, &step.auxiliary_4, &cells.auxiliary_4)?;
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let ref_val = RefValGadget::construct(cb);
        let value_a = ValueGadget::construct(cb);
        let value_b = ValueGadget::construct(cb);

        Self {
            ref_val,
            value_a,
            value_b,
        }
    }
}
