// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, rw_table::RWTarget};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct Pack<const GENERIC: bool, F: FieldExt> {
    values: Vec<Cell<F>>,
    values_mask: Vec<Cell<F>>,
    values_addr_ext_0: Vec<Cell<F>>,
    values_addr_ext_1: Vec<Cell<F>>,
    values_address: Vec<Cell<F>>,
    struct_value: Vec<Cell<F>>,
    struct_value_mask: Vec<Cell<F>>,
    struct_value_addr_ext_0: Vec<Cell<F>>,
    struct_value_addr_ext_1: Vec<Cell<F>>,
}

impl<const GENERIC: bool, F: FieldExt> InstructionGadget<F> for Pack<GENERIC, F> {
    const NAME: &'static str = if GENERIC { "PACK_GENERIC" } else { "PACK" };

    const OPCODE: Opcode = if GENERIC {
        Opcode::PackGeneric
    } else {
        Opcode::Pack
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //Pack

        let field_num = cells.auxiliary_1.expression.clone();
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - field_num.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let struct_value_element_num = cells.auxiliary_3.expression.clone();
        let values_element_num = struct_value_element_num.clone() - 1.expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + values_element_num.clone()
            + struct_value_element_num;
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", pc_expr),
            ("stack size", stack_size_expr),
            ("frame index", frame_index_expr),
            ("pack gc", gc_expr),
            ("module index", module_index),
            ("function index", func_index),
        ]);

        // read values from stack, write back the packed struct
        // struct_value[0] is the header. To make the constraint simple, we have already
        // assigned the values[0] to be empty, now we just skip 'i=0'.
        for (i, item) in self.values.iter().enumerate().skip(1) {
            cb.condition(1.expr() - self.values_mask[i].expression.clone(), |cb| {
                cb.add_lookup(
                    "pack(stack pop)",
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
                );
            });

            cb.condition(
                1.expr() - self.struct_value_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup(
                        "pack(stack push)",
                        RWLookup::stack_push(
                            cells.gc.expression.clone()
                                + values_element_num.clone()
                                + (i as u64).expr(),
                            cells.stack_size.expression.clone() - field_num.clone(),
                            self.struct_value_addr_ext_0[i].expression.clone(),
                            self.struct_value_addr_ext_1[i].expression.clone(),
                            item.expression.clone(),
                        ),
                    );
                },
            );
        }
        cb.condition(
            1.expr() - self.struct_value_mask[0].expression.clone(),
            |cb| {
                cb.add_lookup(
                    "pack(write struct header)",
                    RWLookup::stack_push(
                        cells.gc.expression.clone() + values_element_num,
                        cells.stack_size.expression.clone() - field_num,
                        self.struct_value_addr_ext_0[0].expression.clone(),
                        self.struct_value_addr_ext_1[0].expression.clone(),
                        self.struct_value[0].expression.clone(),
                    ),
                );
            },
        );
        // word_b.address is equal to word_a.address_ext_0
        // word_b.address_ext_0 is equal to word_a.address_ext_1
        for (i, _) in self.struct_value.iter().enumerate().skip(1) {
            let constraint = self.struct_value_mask[i].expression.clone()
                * (self.values_address[i].expression.clone()
                    - self.struct_value_addr_ext_0[i].expression.clone());
            cb.add_constraint("pack_address_eq", constraint);
            let constraint = self.struct_value_mask[i].expression.clone()
                * (self.values_addr_ext_0[i].expression.clone()
                    - self.struct_value_addr_ext_1[i].expression.clone());
            cb.add_constraint("pack_address_ext_0_eq", constraint);
        }

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Self::OPCODE,
            cells.auxiliary_2.expression.clone(),
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
        let _field_num =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;
        let _sd_idx =
            Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
        let struct_value_element_num =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;
        let values_element_num = struct_value_element_num - 1;

        let values = Word {
            word: self.values.clone(),
            word_mask: self.values_mask.clone(),
            word_addr_ext_0: self.values_addr_ext_0.clone(),
            word_addr_ext_1: self.values_addr_ext_1.clone(),
        };
        Word::assign_word_with_address(
            region,
            offset,
            rw_operations,
            &values,
            &self.values_address,
            step.gc,
            values_element_num,
        )?;

        let struct_value = Word {
            word: self.struct_value.clone(),
            word_mask: self.struct_value_mask.clone(),
            word_addr_ext_0: self.struct_value_addr_ext_0.clone(),
            word_addr_ext_1: self.struct_value_addr_ext_1.clone(),
        };
        Word::assign_word(
            region,
            offset,
            step,
            rw_operations,
            &struct_value,
            step.gc + values_element_num,
            struct_value_element_num,
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let values = cb.alloc_n_cells(word_cap);
        let values_mask = cb.alloc_n_cells(word_cap);
        let values_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let values_addr_ext_1 = cb.alloc_n_cells(word_cap);
        let values_address = cb.alloc_n_cells(word_cap);
        let struct_value = cb.alloc_n_cells(word_cap);
        let struct_value_mask = cb.alloc_n_cells(word_cap);
        let struct_value_addr_ext_0 = cb.alloc_n_cells(word_cap);
        let struct_value_addr_ext_1 = cb.alloc_n_cells(word_cap);

        Self {
            values,
            values_mask,
            values_addr_ext_0,
            values_addr_ext_1,
            values_address,
            struct_value,
            struct_value_mask,
            struct_value_addr_ext_0,
            struct_value_addr_ext_1,
        }
    }
}
