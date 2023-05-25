// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, RefVal, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct VecBorrow<const MUTABLE: bool, F: FieldExt> {
    index: Cell<F>,
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,

    indexed_ref_val: Vec<Cell<F>>,
    indexed_ref_val_mask: Vec<Cell<F>>,
}

impl<const MUTABLE: bool, F: FieldExt> InstructionGadget<F> for VecBorrow<MUTABLE, F> {
    const NAME: &'static str = "VEC_BORROW";

    const OPCODE: Opcode = if MUTABLE {
        Opcode::VecMutBorrow
    } else {
        Opcode::VecImmBorrow
    };

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction VecMut(Imm)Borrow, there are 3 steps here:
        // 1. read index from stack. [gc, 1]
        // 1. read reference from stack. [gc + 1, DEPTH_OF_ADDRESS_PATH]
        // 3. write reference to element into stack.
        // [gc + 1 + DEPTH_OF_ADDRESS_PATH, DEPTH_OF_ADDRESS_PATH]
        let opcode = if MUTABLE {
            Opcode::VecMutBorrow
        } else {
            Opcode::VecImmBorrow
        };
        let cond = cells.conditions[opcode.index()].expression.clone();

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + 2.expr() * depth_of_addr_path_expr.clone()
            + 1.expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        // lookup "read index"
        lookups.rw_lookups.push((
            "vec_borrow(read index)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                self.index.expression.clone(),
                0.expr(),
            ),
            cond.clone(),
        ));

        // Todo. need to parse addr_ext.
        for (i, item) in self.indexed_ref_val.iter().enumerate().take(2) {
            // lookup "read vec ref"
            lookups.rw_lookups.push((
                "vec_borrow(read vec ref)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + 1.expr() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 1.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.ref_val_mask[i].expression.clone()),
            ));

            // lookup "write indexed ref"
            lookups.rw_lookups.push((
                "vec_borrow(write indexed ref)",
                RWLookup::stack_push(
                    cells.gc.expression.clone()
                        + depth_of_addr_path_expr.clone()
                        + 1.expr()
                        + (i as u64).expr(),
                    cells.stack_size.expression.clone() - 2.expr(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                    0.expr(),
                ),
                cond.clone() * (1.expr() - self.indexed_ref_val_mask[i].expression.clone()),
            ));
        }

        // element index should be equal to indexed_ref_val[last],
        // NOTICE: counting the header, it's 1 larger than the real offset
        let index = self.index.expression.clone();
        for i in 0..DEPTH_OF_ADDRESS_PATH {
            let constraint = cond.clone()
                * self.ref_val_mask[i].expression.clone()
                * (1.expr() - self.indexed_ref_val_mask[i].expression.clone())
                * (index.clone() + 1.expr() - self.indexed_ref_val[i].expression.clone());
            cb.add_constraint("borrow_element_index_eq", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cells,
            opcode,
            cells.auxiliary_1.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
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
        let ref_val_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        self.index.assign(region, offset, op.value().value())?;

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
            step.gc + 1,
            ref_val_flattened_len,
        )?;

        let indexed_ref_val = RefVal {
            ref_val: self.indexed_ref_val.clone(),
            ref_val_mask: self.indexed_ref_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &indexed_ref_val,
            step.gc + 1 + DEPTH_OF_ADDRESS_PATH,
            ref_val_flattened_len + 1, // the last element is element index
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let index = cb.alloc_cell();
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        let indexed_ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let indexed_ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        Self {
            index,
            ref_val,
            ref_val_mask,

            indexed_ref_val,
            indexed_ref_val_mask,
        }
    }
}
