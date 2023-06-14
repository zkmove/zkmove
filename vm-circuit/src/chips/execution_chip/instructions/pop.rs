// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct Pop<F: FieldExt> {
    word_a: Vec<Cell<F>>,
    word_a_mask: Vec<Cell<F>>,
    word_a_addr_ext_0: Vec<Cell<F>>,
    word_a_addr_ext_1: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Pop<F> {
    const NAME: &'static str = "POP";

    const OPCODE: Opcode = Opcode::Pop;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let word_element_num = cells.auxiliary_3.expression.clone();
        let gc_expr =
            cells.gc.expression.clone() - cb.next.cells.gc.expression.clone() + word_element_num;
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

        for (i, _) in self.word_a.iter().enumerate() {
            cb.condition(1.expr() - self.word_a_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "pop(stack)",
                    RWLookup::stack_pop(
                        cells.gc.expression.clone() + (i as u64).expr(),
                        cells.stack_size.expression.clone(),
                        self.word_a_addr_ext_0[i].expression.clone(),
                        self.word_a_addr_ext_1[i].expression.clone(),
                        self.word_a[i].expression.clone(),
                    ),
                );
            });
        }

        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Pop, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
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
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let word_a = cb.alloc_n_cells(word_cap);
        let word_a_mask = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let word_a_addr_ext_1 = cb.alloc_n_cells(word_cap);

        Self {
            word_a,
            word_a_mask,
            word_a_addr_ext_0,
            word_a_addr_ext_1,
        }
    }
}
