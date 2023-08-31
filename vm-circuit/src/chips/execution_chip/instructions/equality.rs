// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::instructions::common::simple_value_gadget::SimpleValueGadget;
use crate::chips::execution_chip::instructions::common::value_gadget::ValueGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::{RWLookup, RWTarget};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::base_constraint_builder::BaseConstraintBuilder;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::DeltaInvert;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::error;
use movelang::value_ext::ValueHeader;

#[derive(Clone, Debug)]
pub struct Equality<const EQUALITY: bool, F: FieldExt> {
    value_a: ValueGadget<F>, // right
    value_b: ValueGadget<F>, // left
    result: SimpleValueGadget<F>,

    unequal_row_addr_ext_a: Cell<F>,
    unequal_row_value_a: Cell<F>,
    unequal_row_addr_ext_b: Cell<F>,
    unequal_row_value_b: Cell<F>,
    delta_invert: Cell<F>,
}

impl<const EQUALITY: bool, F: FieldExt> InstructionGadget<F> for Equality<EQUALITY, F> {
    const NAME: &'static str = match EQUALITY {
        true => "EQ",
        false => "NEQ",
    };

    const OPCODE: Opcode = match EQUALITY {
        true => Opcode::Eq,
        false => Opcode::Neq,
    };

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let flattened_value_len_a = cells.auxiliary_1.expression.clone();
        let flattened_value_len_b = cells.auxiliary_2.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + flattened_value_len_a.clone()
            + flattened_value_len_b.clone()
            + 2.expr(); // bool result
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

        let mut bcb = BaseConstraintBuilder::default();
        self.value_a.configure(cb, flattened_value_len_a.clone());
        self.value_b.configure(cb, flattened_value_len_b.clone());
        self.result.configure(cb);
        bcb.require_boolean(
            "result is bool",
            self.result.cells.value().expression.clone(),
        );
        let is_reference = cells.auxiliary_3.expression.clone();
        bcb.require_boolean("is_reference is bool", is_reference.clone());

        let a_equal_b_expr = match EQUALITY {
            true => self.result.cells.value().expression.clone(),
            false => 1.expr() - self.result.cells.value().expression.clone(),
        };
        let a_unequal_b_expr = match EQUALITY {
            true => 1.expr() - self.result.cells.value().expression.clone(),
            false => self.result.cells.value().expression.clone(),
        };

        for (i, item) in self.value_a.cells.word.iter().enumerate() {
            cb.condition(
                1.expr() - self.value_a.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup(
                        "equality(pop right)",
                        RWLookup::stack_pop(
                            cells.gc.expression.clone() + (i as u64).expr(),
                            cells.stack_size.expression.clone(),
                            self.value_a.cells.word_addr_ext[i].expression.clone(),
                            item.expression.clone(),
                        ),
                    );
                },
            );
        }
        for (i, item) in self.value_b.cells.word.iter().enumerate() {
            cb.condition(
                1.expr() - self.value_b.cells.word_mask[i].expression.clone(),
                |cb| {
                    cb.add_lookup(
                        "equality(pop left)",
                        RWLookup::stack_pop(
                            cells.gc.expression.clone()
                                + flattened_value_len_a.clone()
                                + (i as u64).expr(),
                            cells.stack_size.expression.clone() - 1.expr(),
                            self.value_b.cells.word_addr_ext[i].expression.clone(),
                            item.expression.clone(),
                        ),
                    );
                },
            );
        }

        // value_a is equal to value_b
        for (i, item) in self.value_a.cells.word.iter().enumerate() {
            cb.condition(
                (1.expr() - self.value_a.cells.word_mask[i].expression.clone())
                    * (1.expr() - is_reference.clone())
                    * a_equal_b_expr.clone(),
                |cb| {
                    // lookup a's addr_ext/value in b's ops, success means a is equal to b
                    cb.add_lookup(
                        "equality(equality check)",
                        RWLookup::stack_pop(
                            cells.gc.expression.clone()
                                + flattened_value_len_a.clone()
                                + (i as u64).expr(),
                            cells.stack_size.expression.clone() - 1.expr(),
                            self.value_a.cells.word_addr_ext[i].expression.clone(),
                            item.expression.clone(),
                        ),
                    );
                },
            );
        }

        // value_a is unequal to value_b
        cb.condition((1.expr() - is_reference) * a_unequal_b_expr, |cb| {
            let unequal_row = cells.auxiliary_4.expression.clone();
            let unequal_column = cells.auxiliary_5.expression.clone();

            cb.add_lookup(
                "equality(right unequal row)",
                RWLookup {
                    gc: cells.gc.expression.clone() + unequal_row.clone(),
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    frame_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - 1.expr(),
                    address_ext: self.unequal_row_addr_ext_a.expression.clone(),
                    value: self.unequal_row_value_a.expression.clone(),
                    sd_index: 0.expr(),
                },
            );
            cb.add_lookup(
                "equality(left unequal row)",
                RWLookup {
                    gc: cells.gc.expression.clone() + flattened_value_len_a.clone() + unequal_row,
                    rw_target: (RWTarget::Stack as u64).expr(),
                    rw: (RW::READ as u64).expr(),
                    frame_index: 0.expr(),
                    address: cells.stack_size.expression.clone() - 2.expr(),
                    address_ext: self.unequal_row_addr_ext_b.expression.clone(),
                    value: self.unequal_row_value_b.expression.clone(),
                    sd_index: 0.expr(),
                },
            );

            // column addr_ext unequal
            cb.condition(1.expr() - unequal_column.clone(), |cb| {
                // constrain delta_invert
                let constraint_1 = ((self.unequal_row_addr_ext_a.expression.clone()
                    - self.unequal_row_addr_ext_b.expression.clone())
                    * self.delta_invert.expression.clone()
                    - 1.expr())
                    * (self.unequal_row_addr_ext_a.expression.clone()
                        - self.unequal_row_addr_ext_b.expression.clone());
                // constrain "unequal_row_addr_ext_a != unequal_row_addr_ext_b"
                let constraint_2 = (self.unequal_row_addr_ext_a.expression.clone()
                    - self.unequal_row_addr_ext_b.expression.clone())
                    * self.delta_invert.expression.clone()
                    - 1.expr();

                cb.add_constraint("delta_invert", constraint_1);
                cb.add_constraint("unequal addr_ext", constraint_2);
            });

            // column value unequal
            cb.condition(unequal_column, |cb| {
                // constrain delta_invert
                let constraint_1 = ((self.unequal_row_value_a.expression.clone()
                    - self.unequal_row_value_b.expression.clone())
                    * self.delta_invert.expression.clone()
                    - 1.expr())
                    * (self.unequal_row_value_a.expression.clone()
                        - self.unequal_row_value_b.expression.clone());
                let constraint_2 = (self.unequal_row_value_a.expression.clone()
                    - self.unequal_row_value_b.expression.clone())
                    * self.delta_invert.expression.clone()
                    - 1.expr();
                // constrain "unequal_row_value_a != unequal_row_value_b"
                cb.add_constraint("delta_invert", constraint_1);
                cb.add_constraint("unequal value", constraint_2);
            });
        });

        // TODO: handle "is_reference == true"

        // stack write
        let write = RWLookup::stack_push(
            cells.gc.expression.clone()
                + flattened_value_len_a.clone()
                + flattened_value_len_b.clone(),
            cells.stack_size.expression.clone() - 2.expr(),
            0.expr(),
            ValueHeader::default_for_simple().expr(),
        );
        cb.add_lookup("equality(push result header)", write);
        let write = RWLookup::stack_push(
            cells.gc.expression.clone() + flattened_value_len_a + flattened_value_len_b + 1.expr(),
            cells.stack_size.expression.clone() - 2.expr(),
            1.expr(),
            self.result.cells.value().expression.clone(),
        );
        cb.add_lookup("equality(push result value)", write);

        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, 0.expr());

        cb.add_constraints(bcb.constraints);
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let flattened_value_len_a =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?
                .get_lower_128() as usize;
        let flattened_value_len_b =
            Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?
                .get_lower_128() as usize;
        let _is_reference =
            Word::assign_step_value(region, offset, &step.auxiliary_3, &cells.auxiliary_3)?
                .get_lower_128() as usize;

        self.value_a.assign(
            region,
            offset,
            rw_operations,
            step.gc,
            flattened_value_len_a,
        )?;
        self.value_b.assign(
            region,
            offset,
            rw_operations,
            step.gc + flattened_value_len_a,
            flattened_value_len_b,
        )?;
        self.result.assign(
            region,
            offset,
            rw_operations,
            step.gc + flattened_value_len_a + flattened_value_len_b,
        )?;

        // assign unequal_row_xxx, delta_invert
        let result_op = rw_operations
            .0
            .get(step.gc + flattened_value_len_a + flattened_value_len_b + 1)
            .ok_or(Error::Synthesis)?;
        let a_unequal_b = if EQUALITY { F::zero() } else { F::one() };
        if result_op.value().value() == Some(a_unequal_b) {
            // a and b are not equal
            let unequal_row =
                Word::assign_step_value(region, offset, &step.auxiliary_4, &cells.auxiliary_4)?
                    .get_lower_128() as usize;
            let unequal_column =
                Word::assign_step_value(region, offset, &step.auxiliary_5, &cells.auxiliary_5)?
                    .get_lower_128() as usize;

            let unequal_op_a = rw_operations
                .0
                .get(step.gc + unequal_row)
                .ok_or(Error::Synthesis)?;
            let unequal_op_b = rw_operations
                .0
                .get(step.gc + flattened_value_len_a + unequal_row)
                .ok_or(Error::Synthesis)?;
            let addr_ext_a = F::from_u128(unequal_op_a.address_ext() as u128);
            let addr_ext_b = F::from_u128(unequal_op_b.address_ext() as u128);
            let val_a = unequal_op_a.value().value().ok_or_else(|| {
                error!("value is None");
                Error::Synthesis
            })?;
            let val_b = unequal_op_b.value().value().ok_or_else(|| {
                error!("value is None");
                Error::Synthesis
            })?;
            self.unequal_row_addr_ext_a
                .assign(region, offset, Some(addr_ext_a))?;
            self.unequal_row_addr_ext_b
                .assign(region, offset, Some(addr_ext_b))?;
            self.unequal_row_value_a
                .assign(region, offset, Some(val_a))?;
            self.unequal_row_value_b
                .assign(region, offset, Some(val_b))?;
            match unequal_column {
                0 => {
                    self.delta_invert.assign(
                        region,
                        offset,
                        addr_ext_a.delta_invert(addr_ext_b),
                    )?;
                }
                1 => {
                    self.delta_invert
                        .assign(region, offset, val_a.delta_invert(val_b))?;
                }
                _ => {}
            };
        }
        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = ValueGadget::construct(cb);
        let value_b = ValueGadget::construct(cb);
        let result = SimpleValueGadget::construct(cb);

        let unequal_row_addr_ext_a = cb.alloc_cell();
        let unequal_row_value_a = cb.alloc_cell();
        let unequal_row_addr_ext_b = cb.alloc_cell();
        let unequal_row_value_b = cb.alloc_cell();
        let delta_invert = cb.alloc_cell();

        Self {
            value_a,
            value_b,
            result,

            unequal_row_addr_ext_a,
            unequal_row_value_a,
            unequal_row_addr_ext_b,
            unequal_row_value_b,
            delta_invert,
        }
    }
}
