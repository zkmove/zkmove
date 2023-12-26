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
pub struct BorrowLoc<const MUTABLE: bool, F: Field> {
    value: ValueGadget<F>,
    ref_val: RefValGadget<F>,
}

impl<const MUTABLE: bool, F: Field> InstructionGadget<F> for BorrowLoc<MUTABLE, F> {
    const NAME: &'static str = "BORROWLOC";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::MutBorrowLoc
    } else {
        Opcode::ImmBorrowLoc
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let flattened_value_len = cells.auxiliary_3.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + flattened_value_len.clone()
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
        self.ref_val.configure(cb);

        for (i, _) in self.value.cells.word.iter().enumerate() {
            cb.condition(
                1u64.expr() - self.value.cells.word_mask[i].expression.clone(),
                |cb| {
                    let read = RWLookup::locals_read(
                        cells.gc.expression.clone() + (i as u64).expr(),
                        cells.frame_index.expression.clone(),
                        cells.locals_index.expression.clone(),
                        self.value.cells.word_addr_ext[i].expression.clone(),
                        self.value.cells.word[i].expression.clone(),
                    );

                    cb.add_lookup("borrow_local(read locals)", read);
                },
            );
        }

        for (i, item) in self.ref_val.cells.as_inner().iter().enumerate() {
            cb.add_lookup(
                "borrow_local(stack push ref_val)",
                RWLookup::stack_push(
                    cells.gc.expression.clone() + flattened_value_len.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // ref_val[1] == frame_index && ref_val[2] == locals_index;
        cb.add_constraint(
            "borrow_locals_ref_eq_0",
            self.ref_val.cells[0].expression.clone() - ValueHeader::default_for_ref_val().expr(),
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_1",
            self.ref_val.cells[1].expression.clone() - cells.frame_index.expression.clone(),
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_2",
            self.ref_val.cells[2].expression.clone() - cells.locals_index.expression.clone(),
        );
        cb.add_constraint(
            "borrow_locals_ref_eq_3",
            self.ref_val.cells[3].expression.clone(),
        );

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            cells.locals_index.expression.clone(),
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let flattened_value_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.value
            .assign(region, offset, rw_operations, step.gc, flattened_value_len)?;

        self.ref_val
            .assign(region, offset, rw_operations, step.gc + flattened_value_len)?;
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value = ValueGadget::construct(cb);
        let ref_val = RefValGadget::construct(cb);

        Self { value, ref_val }
    }
}
