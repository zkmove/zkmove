// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::reference_value_gadget::RefValGadget;
use crate::chips::execution_chip::instructions::common::simple_value_gadget::SimpleValueGadget;
use crate::chips::execution_chip::instructions::common::{AddrExt, LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::flattened_value::LEN_OF_REFERENCE_VALUE;
use movelang::flattened_value::{ValueHeader, LEN_OF_SIMPLE_VALUE};

#[derive(Clone, Debug)]
pub struct VecBorrow<const MUTABLE: bool, F: FieldExt> {
    index: SimpleValueGadget<F>,
    offset_pow2: Cell<F>,
    ref_val: RefValGadget<F>,
    indexed_ref_val: RefValGadget<F>,
}

impl<const MUTABLE: bool, F: FieldExt> InstructionGadget<F> for VecBorrow<MUTABLE, F> {
    const NAME: &'static str = "VEC_BORROW";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::VecMutBorrow
    } else {
        Opcode::VecImmBorrow
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction VecMut(Imm)Borrow, there are 3 steps here:
        // 1. read index from stack. [gc, 2]
        // 2. read reference from stack. [gc + 2, LEN_OF_REFERENCE_VALUE]
        // 3. write reference to element into stack.
        // [gc + 2 + LEN_OF_REFERENCE_VALUE, LEN_OF_REFERENCE_VALUE]

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * (LEN_OF_REFERENCE_VALUE as u64).expr()
            + 2.expr();
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

        self.index.configure(cb);
        self.ref_val.configure(cb);
        self.indexed_ref_val.configure(cb);

        // lookup "read index"
        cb.add_lookup(
            "vec_borrow(read value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "vec_borrow(read index)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                self.index.cells.value().expression.clone(),
            ),
        );

        for (i, item) in self.ref_val.cells.as_inner().iter().enumerate() {
            // lookup "read vec ref"
            cb.add_lookup(
                "vec_borrow(read vec ref)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone()
                        + (LEN_OF_SIMPLE_VALUE as u64).expr()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }
        for (i, item) in self.indexed_ref_val.cells.as_inner().iter().enumerate() {
            // lookup "write indexed ref"
            cb.add_lookup(
                "vec_borrow(write indexed ref)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + (LEN_OF_SIMPLE_VALUE as u64).expr()
                        + (LEN_OF_REFERENCE_VALUE as u64).expr()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 2.expr(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        // location check between ref_val and indexed_ref_val
        AddrExt::location_val_constrain(
            cb,
            self.ref_val.cells.as_inner(),
            self.indexed_ref_val.cells.as_inner(),
        )
        .expect("location chck failed");

        // addr_ext comparation between ref_val and indexed_ref_val
        // field_offset is pushed into the last element of indexed_ref_val,
        // and it's larger than the real offset by 1
        let constraint = self.ref_val.cells[3].expression.clone()
            + (self.index.cells.value().expression.clone() + 1.expr())
                * self.offset_pow2.expression.clone()
            - self.indexed_ref_val.cells[3].expression.clone();
        cb.add_constraint("field_offset check with ref_val[3]", constraint);

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            cells.auxiliary_1.expression.clone(),
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
        let _si = Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        // let _ref_val_flattened_len =
        //     Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
        //         .get_lower_128() as usize;
        let _pow2 = Word::assign_offset_pow2(region, offset, &step.auxiliary_3, &self.offset_pow2)?
            .get_lower_128() as usize;

        self.index.assign(region, offset, rw_operations, step.gc)?;
        self.ref_val
            .assign(region, offset, rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        self.indexed_ref_val.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE + LEN_OF_REFERENCE_VALUE,
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let index = SimpleValueGadget::construct(cb);
        let offset_pow2 = cb.alloc_cell();

        let ref_val = RefValGadget::construct(cb);
        let indexed_ref_val = RefValGadget::construct(cb);

        Self {
            index,
            offset_pow2,
            ref_val,
            indexed_ref_val,
        }
    }
}
