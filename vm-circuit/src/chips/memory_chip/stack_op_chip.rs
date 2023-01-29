// Copyright (c) zkMove Authors

use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{ConvertedRWOperation, RW};
use crate::witness::CircuitConfig;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STACK_OP_CHIP_WIDTH: usize = 8;

#[derive(Clone, Debug)]
pub struct StackOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of stack operations
    pub address: Cell<F>,
    pub nested_address_0: Cell<F>,
    pub nested_address_1: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_nested_address_0: Cell<F>,
    pub prev_nested_address_1: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StackOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: StackOpCells<F>,
    pub s_first_stack_op: Selector,
    pub s_stack_op: Selector,
}

pub struct StackOpChip<F: FieldExt> {
    pub config: StackOpChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for StackOpChip<F> {
    type Config = StackOpChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> StackOpChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; MEM_CHIP_WIDTH],
        gc_table: &TableColumn,
    ) -> <Self as Chip<F>>::Config {
        let mut cells = VecDeque::with_capacity(STACK_OP_CHIP_WIDTH * 2);
        meta.create_gate("stack op chip", |meta| {
            for i in 0..STACK_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op
            for i in 0..STACK_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = StackOpCells {
            counter: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            address: cells.pop_front().unwrap(),
            nested_address_0: cells.pop_front().unwrap(),
            nested_address_1: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            prev_counter: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
            prev_nested_address_0: cells.pop_front().unwrap(),
            prev_nested_address_1: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_is_empty: cells.pop_front().unwrap(),
        };

        let s_first_stack_op = meta.complex_selector();
        Self::config_stack_op(meta, s_first_stack_op, &cells, true, gc_table);

        let s_stack_op = meta.complex_selector();
        Self::config_stack_op(meta, s_stack_op, &cells, false, gc_table);

        StackOpChipConfig {
            advices,
            cells,
            s_first_stack_op,
            s_stack_op,
        }
    }

    fn config_stack_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &StackOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        Self::constrain_stack_op(cells, &mut constraints, is_first_op, &mut gc_lookups);

        meta.create_gate("constrain stack op", |meta| {
            let selector = meta.query_selector(selector);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, selector.clone() * constraint))
        });

        for lookup in gc_lookups {
            meta.lookup(|meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *gc_table)]
            });
        }

        // todo: lookup nested_address_0, nested_address_1 for range check
    }

    fn constrain_stack_op(
        cells: &StackOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
    ) {
        constraints.push((
            "is_empty is bool",
            (cells.is_empty.expression.clone() - 1.expr()) * cells.is_empty.expression.clone(),
        ));
        let cond = 1.expr() - cells.is_empty.expression.clone();

        if is_first {
            // for the first op: counter == 1, address == 0, rw == Write
            constraints.push((
                "first stack op",
                cond.clone() * (cells.counter.expression.clone() - 1.expr()),
            ));
            constraints.push((
                "first stack op",
                cond.clone() * cells.address.expression.clone(),
            ));
            constraints.push((
                "first stack op",
                cond * (cells.rw.expression.clone() - (RW::WRITE as u64).expr()),
            ));
        } else {
            // counter == prev_counter + 1
            constraints.push((
                "counter",
                cond.clone()
                    * (cells.counter.expression.clone()
                        - cells.prev_counter.expression.clone()
                        - 1.expr()),
            ));
            // 'address == prev_address' or 'address == prev_address + 1'
            let delt_addr =
                cells.address.expression.clone() - cells.prev_address.expression.clone();
            constraints.push((
                "address",
                cond.clone() * (delt_addr.clone() * (delt_addr.clone() - 1.expr())),
            ));

            //todo: nested_address monotonic increment

            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // if address != prev_address then rw == Write
            // todo: take nested_address into consideration, and the first nested_address must be a Write
            constraints.push((
                "address ",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * delt_addr.clone(),
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1.expr()),
            ));

            // todo: address must be less than EVAL_STACK_SIZE

            // for ops with same address, gc must be greater than prev_gc
            gc_lookups.push(
                cond * (1.expr() - delt_addr)
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // empty op
            constraints.push((
                "empty op counter",
                cells.is_empty.expression.clone()
                    * (cells.counter.expression.clone() - cells.prev_counter.expression.clone()),
            ));
        }
    }

    // assign each cell of the stack operation, return assigned cell for counter
    pub fn assign_cell(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op: &ConvertedRWOperation<F>,
        counter: usize,
        is_empty: bool,
    ) -> Result<AssignedCell<F, F>, Error> {
        let assigned =
            self.config
                .cells
                .counter
                .assign(region, offset, Some(F::from(counter as u64)))?; //fixme: how about if counter is great than max_u64?

        if is_empty {
            self.config.cells.gc.assign(region, offset, Some(op.gc.0))?;

            self.config.cells.rw.assign(region, offset, Some(op.rw.0))?;

            self.config
                .cells
                .address
                .assign(region, offset, Some(op.address.0))?;

            self.config.cells.nested_address_0.assign(
                region,
                offset,
                Some(op.nested_address_0.0),
            )?;

            self.config.cells.nested_address_1.assign(
                region,
                offset,
                Some(op.nested_address_1.0),
            )?;

            self.config.cells.value.assign(region, offset, op.value.0)?;

            self.config
                .cells
                .is_empty
                .assign(region, offset, Some(F::one()))?;
        } else {
            self.config.cells.gc.assign_equality(
                region,
                offset,
                op.gc.1.clone().ok_or_else(|| {
                    error!("gc assigned cell is None");
                    Error::Synthesis
                })?,
                "gc",
            )?;

            self.config.cells.rw.assign_equality(
                region,
                offset,
                op.rw.1.clone().ok_or_else(|| {
                    error!("rw assigned cell is None");
                    Error::Synthesis
                })?,
                "rw",
            )?;

            self.config.cells.address.assign_equality(
                region,
                offset,
                op.address.1.clone().ok_or_else(|| {
                    error!("address assigned cell is None");
                    Error::Synthesis
                })?,
                "address",
            )?;

            self.config.cells.nested_address_0.assign_equality(
                region,
                offset,
                op.nested_address_0.1.clone().ok_or_else(|| {
                    error!("nested_address_0 assigned cell is None");
                    Error::Synthesis
                })?,
                "nested_address_0",
            )?;

            self.config.cells.nested_address_1.assign_equality(
                region,
                offset,
                op.nested_address_1.1.clone().ok_or_else(|| {
                    error!("nested_address_1 assigned cell is None");
                    Error::Synthesis
                })?,
                "nested_address_1",
            )?;

            self.config.cells.value.assign_equality(
                region,
                offset,
                op.value.1.clone().ok_or_else(|| {
                    error!("value assigned cell is None");
                    Error::Synthesis
                })?,
                "value",
            )?;

            self.config
                .cells
                .is_empty
                .assign(region, offset, Some(F::zero()))?;
        }

        Ok(assigned)
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        _circuit_config: &CircuitConfig,
        stack_ops: Vec<ConvertedRWOperation<F>>,
        stack_ops_num: usize,
    ) -> Option<AssignedCell<F, F>> {
        let mut last_stack_counter: Option<AssignedCell<F, F>> = None;

        if !stack_ops.is_empty() || stack_ops_num > 0 {
            layouter
                .assign_region(
                    || "stack operations",
                    |mut region: Region<'_, F>| {
                        let mut counter = 0;
                        for (index, op) in stack_ops.iter().enumerate() {
                            counter = index + 1;
                            let assigned_counter = if index == 0 {
                                self.config.s_first_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, false)?
                            } else {
                                self.config.s_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, false)?
                            };
                            if counter == stack_ops.len() {
                                last_stack_counter = Some(assigned_counter);
                            }
                        }

                        // If the number of stack ops is less than stack_ops_num set by user, fill with
                        // empty op. This happened when the execution path is not fixed, for example,
                        // if there is loop in the code.
                        if stack_ops.len() < stack_ops_num {
                            for index in stack_ops.len()..stack_ops_num {
                                let assigned_counter = if index == 0 {
                                    self.config.s_first_stack_op.enable(&mut region, index)?;
                                    self.assign_cell(
                                        &mut region,
                                        index,
                                        &ConvertedRWOperation::empty(),
                                        counter,
                                        true,
                                    )?
                                } else {
                                    self.config.s_stack_op.enable(&mut region, index)?;
                                    self.assign_cell(
                                        &mut region,
                                        index,
                                        &ConvertedRWOperation::empty(),
                                        counter,
                                        true,
                                    )?
                                };
                                last_stack_counter = Some(assigned_counter);
                            }
                        }
                        Ok(())
                    },
                )
                .ok()?;
        }
        last_stack_counter
    }
}
