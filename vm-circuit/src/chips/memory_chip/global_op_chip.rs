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

pub const GLOBAL_OP_CHIP_WIDTH: usize = 11;

#[derive(Clone, Debug)]
pub struct GlobalOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of global rw operations
    pub address: Cell<F>,
    pub nested_address_0: Cell<F>,
    pub nested_address_1: Cell<F>,
    pub sd_index: Cell<F>, // struct definition index
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not

    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same global address
    pub delta_invert_address: Cell<F>,
    pub delta_invert_sd_index: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_nested_address_0: Cell<F>,
    pub prev_nested_address_1: Cell<F>,
    pub prev_sd_index: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct GlobalOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: GlobalOpCells<F>,
    pub s_first_global_op: Selector,
    pub s_global_op: Selector,
}

pub struct GlobalOpChip<F: FieldExt> {
    pub config: GlobalOpChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for GlobalOpChip<F> {
    type Config = GlobalOpChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> GlobalOpChip<F> {
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
        let mut cells = VecDeque::with_capacity(GLOBAL_OP_CHIP_WIDTH * 2);
        meta.create_gate("global op chip", |meta| {
            for i in 0..GLOBAL_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op, without delta_invert cells
            for i in 0..(GLOBAL_OP_CHIP_WIDTH - 2) {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = GlobalOpCells {
            counter: cells.pop_front().unwrap(),
            address: cells.pop_front().unwrap(),
            nested_address_0: cells.pop_front().unwrap(),
            nested_address_1: cells.pop_front().unwrap(),
            sd_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_address: cells.pop_front().unwrap(),
            delta_invert_sd_index: cells.pop_front().unwrap(),

            prev_counter: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
            prev_nested_address_0: cells.pop_front().unwrap(),
            prev_nested_address_1: cells.pop_front().unwrap(),
            prev_sd_index: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_is_empty: cells.pop_front().unwrap(),
        };

        let s_first_global_op = meta.complex_selector();
        Self::config_global_op(meta, s_first_global_op, &cells, true, gc_table);

        let s_global_op = meta.complex_selector();
        Self::config_global_op(meta, s_global_op, &cells, false, gc_table);

        GlobalOpChipConfig {
            advices,
            cells,
            s_first_global_op,
            s_global_op,
        }
    }

    fn config_global_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &GlobalOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        Self::constrain_global_op(cells, &mut constraints, is_first_op, &mut gc_lookups);

        meta.create_gate("constrain global op", |meta| {
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

    fn constrain_global_op(
        cells: &GlobalOpCells<F>,
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
            // for the first op: counter == 1
            constraints.push((
                "first global op",
                cond * (cells.counter.expression.clone() - 1.expr()),
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
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // if address/sd_index != prev_address/prev_sd_index and rw == Read
            // todo: check merkle proof

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1.expr()),
            ));

            // for ops with same address/sd_index, gc must be great than prev_gc
            // 1.constrain delta_invert: (a - b) * inverse(a - b) must be 1 or 0
            // 2.lookup gc_table when address/sd_index is same with previous
            // todo: take nested_address into consideration
            let delt_address =
                cells.address.expression.clone() - cells.prev_address.expression.clone();
            constraints.push((
                "delt_invert_address",
                cond.clone()
                    * delt_address.clone()
                    * (delt_address.clone() * cells.delta_invert_address.expression.clone()
                        - 1.expr()),
            ));
            let delt_sd_index =
                cells.sd_index.expression.clone() - cells.prev_sd_index.expression.clone();
            constraints.push((
                "delt_invert_sd_index",
                cond.clone()
                    * delt_sd_index.clone()
                    * (delt_sd_index.clone() * cells.delta_invert_sd_index.expression.clone()
                        - 1.expr()),
            ));
            gc_lookups.push(
                cond * (1.expr() - delt_address * cells.delta_invert_address.expression.clone())
                    * (1.expr() - delt_sd_index * cells.delta_invert_sd_index.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // todo: address must belong to the address list?
            // todo: sd_index must belong to the sd_index list?

            // todo: address must be great than or equal to prev_address
            // todo: for same address, sd_index must be great than or equal to prev_sd_index

            // empty op
            constraints.push((
                "empty op counter",
                cells.is_empty.expression.clone()
                    * (cells.counter.expression.clone() - cells.prev_counter.expression.clone()),
            ));
        }
    }

    // assign each cell of the global rw operation, return assigned cell for counter
    fn assign_cell(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op: &ConvertedRWOperation<F>,
        counter: usize,
        prev_op: Option<ConvertedRWOperation<F>>,
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

            self.config
                .cells
                .sd_index
                .assign(region, offset, Some(op.sd_index.0))?;

            self.config.cells.value.assign(region, offset, op.value.0)?;
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

            self.config.cells.sd_index.assign_equality(
                region,
                offset,
                op.sd_index.1.clone().ok_or_else(|| {
                    error!("sd_index assigned cell is None");
                    Error::Synthesis
                })?,
                "sd_index",
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
        }

        let (prev_address, prev_sd_index) = match prev_op {
            None => (F::zero(), F::zero()),
            Some(v) => (v.address.0, v.sd_index.0),
        };
        self.config.cells.delta_invert_address.assign(
            region,
            offset,
            op.address.0.delta_invert(prev_address),
        )?;
        self.config.cells.delta_invert_sd_index.assign(
            region,
            offset,
            op.sd_index.0.delta_invert(prev_sd_index),
        )?;

        let is_empty = if is_empty { F::one() } else { F::zero() };
        self.config
            .cells
            .is_empty
            .assign(region, offset, Some(is_empty))?;

        Ok(assigned)
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        _circuit_config: &CircuitConfig,
        global_ops: Vec<ConvertedRWOperation<F>>,
        global_ops_num: usize,
    ) -> Option<AssignedCell<F, F>> {
        let mut last_global_counter: Option<AssignedCell<F, F>> = None;

        if !global_ops.is_empty() || global_ops_num > 0 {
            layouter
                .assign_region(
                    || "global operations",
                    |mut region: Region<'_, F>| {
                        let mut prev_op = None;
                        let mut counter = 0;
                        for (index, op) in global_ops.iter().enumerate() {
                            counter = index + 1;
                            let assigned_counter = if index == 0 {
                                self.config.s_first_global_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, false)?
                            } else {
                                self.config.s_global_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, false)?
                            };
                            if counter == global_ops.len() {
                                last_global_counter = Some(assigned_counter);
                            }
                            prev_op = Some(op.clone());
                        }

                        // If the number of global ops is less than global_ops_num set by user, fill with
                        // empty locals op.
                        if global_ops.len() < global_ops_num {
                            for index in global_ops.len()..global_ops_num {
                                let assigned_counter = if index == 0 {
                                    self.config.s_first_global_op.enable(&mut region, index)?;
                                    self.assign_cell(
                                        &mut region,
                                        index,
                                        &ConvertedRWOperation::empty(),
                                        counter,
                                        None,
                                        true,
                                    )?
                                } else {
                                    self.config.s_global_op.enable(&mut region, index)?;
                                    self.assign_cell(
                                        &mut region,
                                        index,
                                        &ConvertedRWOperation::empty(),
                                        counter,
                                        prev_op,
                                        true,
                                    )?
                                };

                                last_global_counter = Some(assigned_counter);
                                prev_op = Some(ConvertedRWOperation::empty());
                            }
                        }

                        Ok(())
                    },
                )
                .ok()?;
        }
        last_global_counter
    }
}
