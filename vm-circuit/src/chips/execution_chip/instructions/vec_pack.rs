// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{
    rw_table::RWLookup, rw_table::RWTarget, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::WORD_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct VecPack<F: FieldExt> {
    // cells for the n values popped from stack
    values: Vec<Cell<F>>,
    values_mask: Vec<Cell<F>>,
    values_addr_ext_0: Vec<Cell<F>>,
    values_addr_ext_1: Vec<Cell<F>>,
    values_address: Vec<Cell<F>>,

    // cells for the vector pushed back
    vector: Vec<Cell<F>>,
    vector_mask: Vec<Cell<F>>,
    vector_addr_ext_0: Vec<Cell<F>>,
    vector_addr_ext_1: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for VecPack<F> {
    const NAME: &'static str = "VEC_PACK";

    const OPCODE: Opcode = Opcode::VecPack;

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction VecPack, there are 2 steps here:
        // 1. read n values from stack. [gc, values_flattened_len]
        // 2. write vector to stack. [gc + values_flattened_len, vector_flattened_len]

        let cond = cells.opcode_selector([Self::OPCODE]);

        let values_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - values_num.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let vector_flattened_len = cells.auxiliary_3.expression.clone();
        let values_flattened_len = vector_flattened_len.clone() - 1.expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + values_flattened_len.clone()
            + vector_flattened_len;
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("vec_pack gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        // read values from stack, write back the packed vector
        // vector[0] is the header. To make the constraint simple, we have already
        // assigned the values[0] to be empty, now we just skip 'i=0'.
        for (i, item) in self.values.iter().enumerate().take(WORD_CAPACITY).skip(1) {
            lookups.rw_lookups.push((
                "vec_pack(read values)",
                RWLookup {
                    gc: cells.gc.expression.clone() + ((i - 1) as u64).expr(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    frame_index: 0.expr(),
                    address: self.values_address[i].expression.clone(),
                    address_ext_0: self.values_addr_ext_0[i].expression.clone(),
                    address_ext_1: self.values_addr_ext_1[i].expression.clone(),
                    value: item.expression.clone(),
                    sd_index: 0.expr(),
                },
                cond.clone() * (1.expr() - self.values_mask[i].expression.clone()),
            ));

            lookups.rw_lookups.push((
                "vec_pack(write vector)",
                RWLookup::stack_push(
                    cells.gc.expression.clone() + values_flattened_len.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone() - values_num.clone(),
                    self.vector_addr_ext_0[i].expression.clone(),
                    self.vector_addr_ext_1[i].expression.clone(),
                    item.expression.clone(),
                ),
                cond.clone() * (1.expr() - self.vector_mask[i].expression.clone()),
            ));
        }

        lookups.rw_lookups.push((
            "vec_pack(write vec header)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + values_flattened_len,
                cells.stack_size.expression.clone() - values_num,
                self.vector_addr_ext_0[0].expression.clone(),
                self.vector_addr_ext_1[0].expression.clone(),
                self.vector[0].expression.clone(),
            ),
            cond.clone() * (1.expr() - self.vector_mask[0].expression.clone()),
        ));

        // values_address is equal to vector_addr_ext_0
        // values_addr_ext_0 is equal to vector_addr_ext_1
        for i in 1..WORD_CAPACITY {
            let constraint = cond.clone()
                * self.vector_mask[i].expression.clone()
                * (self.values_address[i].expression.clone()
                    - self.vector_addr_ext_0[i].expression.clone());
            cb.add_constraint("vec_pack_address_eq", constraint);
            let constraint = cond.clone()
                * self.vector_mask[i].expression.clone()
                * (self.values_addr_ext_0[i].expression.clone()
                    - self.vector_addr_ext_1[i].expression.clone());
            cb.add_constraint("vec_pack_address_ext_0_eq", constraint);
        }

        // todo: add the second operand
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::VecPack,
            cells.auxiliary_2.expression.clone(),
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
        let _values_num =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let _si = Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
        let vector_flattened_len =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;
        let values_flattened_len = vector_flattened_len - 1;

        let values = Word {
            word: self.values.clone(),
            word_mask: self.values_mask.clone(),
            word_addr_ext_0: self.values_addr_ext_0.clone(),
            word_addr_ext_1: self.values_addr_ext_1.clone(),
        };
        // assign the values into a word
        // NOTICE: assign word[0] to be empty, to make the constraints simple
        Word::assign_word_with_address(
            region,
            offset,
            rw_operations,
            &values,
            &self.values_address,
            step.gc,
            values_flattened_len,
        )?;

        let vector = Word {
            word: self.vector.clone(),
            word_mask: self.vector_mask.clone(),
            word_addr_ext_0: self.vector_addr_ext_0.clone(),
            word_addr_ext_1: self.vector_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &vector,
            step.gc + values_flattened_len,
            vector_flattened_len,
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let values = cb.alloc_n_cells(WORD_CAPACITY);
        let values_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let values_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let values_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);
        let values_address = cb.alloc_n_cells(WORD_CAPACITY);

        let vector = cb.alloc_n_cells(WORD_CAPACITY);
        let vector_mask = cb.alloc_n_cells(WORD_CAPACITY);
        let vector_addr_ext_0 = cb.alloc_n_cells(WORD_CAPACITY);
        let vector_addr_ext_1 = cb.alloc_n_cells(WORD_CAPACITY);

        Self {
            values,
            values_mask,
            values_addr_ext_0,
            values_addr_ext_1,
            values_address,

            vector,
            vector_mask,
            vector_addr_ext_0,
            vector_addr_ext_1,
        }
    }
}
