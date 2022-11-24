// Copyright (c) zkMove Authors

use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{ConvertedRWOperation, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const LOCALS_OP_CHIP_WIDTH: usize = 9;

#[derive(Clone, Debug)]
pub struct LocalsOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of locals operations
    pub call_index: Cell<F>,
    pub index: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not
    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same locals
    pub delta_invert_call_index: Cell<F>,
    pub delta_invert_index: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_call_index: Cell<F>,
    pub prev_index: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct LocalsOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: LocalsOpCells<F>,
    pub s_first_locals_op: Selector,
    pub s_locals_op: Selector,
}

pub struct LocalsOpChip<F: FieldExt> {
    pub config: LocalsOpChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for LocalsOpChip<F> {
    type Config = LocalsOpChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> LocalsOpChip<F> {
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
        call_index_table: &TableColumn,
        locals_index_table: &TableColumn,
    ) -> <Self as Chip<F>>::Config {
        let mut cells = VecDeque::with_capacity(LOCALS_OP_CHIP_WIDTH * 2);
        meta.create_gate("locals op chip", |meta| {
            for i in 0..LOCALS_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op, without delta_invert cells
            for i in 0..(LOCALS_OP_CHIP_WIDTH - 2) {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = LocalsOpCells {
            counter: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_call_index: cells.pop_front().unwrap(),
            delta_invert_index: cells.pop_front().unwrap(),

            prev_counter: cells.pop_front().unwrap(),
            prev_call_index: cells.pop_front().unwrap(),
            prev_index: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_is_empty: cells.pop_front().unwrap(),
        };

        let s_first_locals_op = meta.complex_selector();
        Self::config_locals_op(
            meta,
            s_first_locals_op,
            &cells,
            true,
            gc_table,
            call_index_table,
            locals_index_table,
        );

        let s_locals_op = meta.complex_selector();
        Self::config_locals_op(
            meta,
            s_locals_op,
            &cells,
            false,
            gc_table,
            call_index_table,
            locals_index_table,
        );

        LocalsOpChipConfig {
            advices,
            cells,
            s_first_locals_op,
            s_locals_op,
        }
    }

    fn config_locals_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &LocalsOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
        call_index_table: &TableColumn,
        locals_index_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        let mut call_index_lookups = Vec::new();
        let mut locals_index_lookups = Vec::new();
        Self::constrain_locals_op(
            cells,
            &mut constraints,
            is_first_op,
            &mut gc_lookups,
            &mut call_index_lookups,
            &mut locals_index_lookups,
        );

        meta.create_gate("constrain locals op", |meta| {
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

        for lookup in call_index_lookups {
            meta.lookup(|meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *call_index_table)]
            });
        }

        for lookup in locals_index_lookups {
            meta.lookup(|meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *locals_index_table)]
            });
        }
    }

    fn constrain_locals_op(
        cells: &LocalsOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
        call_index_lookups: &mut Vec<Expression<F>>,
        locals_index_lookups: &mut Vec<Expression<F>>,
    ) {
        constraints.push((
            "is_empty is bool",
            (cells.is_empty.expression.clone() - 1.expr()) * cells.is_empty.expression.clone(),
        ));
        let cond = 1.expr() - cells.is_empty.expression.clone();

        if is_first {
            // for the first op: counter == 1, rw == Write
            // note, ether call_index or index may NOT be 0
            constraints.push((
                "first locals op",
                cond.clone() * (cells.counter.expression.clone() - 1.expr()),
            ));
            constraints.push((
                "first locals op",
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
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // if index != prev_index then rw == Write
            let delt_index = cells.index.expression.clone() - cells.prev_index.expression.clone();
            constraints.push((
                "index",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * delt_index.clone(),
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1.expr()),
            ));

            // for ops with same call_index/index, gc must be great than prev_gc
            // 1.constrain delta_invert: (a - b) * inverse(a - b) must be 1 or 0
            // 2.lookup gc_table when call_index/index is same with previous
            let delt_call_index =
                cells.call_index.expression.clone() - cells.prev_call_index.expression.clone();
            constraints.push((
                "delt_invert_call_index",
                cond.clone()
                    * delt_call_index.clone()
                    * (delt_call_index.clone() * cells.delta_invert_call_index.expression.clone()
                        - 1.expr()),
            ));
            constraints.push((
                "delt_invert_index",
                cond.clone()
                    * delt_index.clone()
                    * (delt_index.clone() * cells.delta_invert_index.expression.clone() - 1.expr()),
            ));
            gc_lookups.push(
                cond.clone()
                    * (1.expr()
                        - delt_call_index.clone()
                            * cells.delta_invert_call_index.expression.clone())
                    * (1.expr() - delt_index * cells.delta_invert_index.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // call_index must be less than max_call_index
            call_index_lookups.push(cond.clone() * cells.call_index.expression.clone());
            // index must be less than max_locals_size
            locals_index_lookups.push(cond.clone() * cells.index.expression.clone());
            // call_index must be great than or equal to prev_call_index
            call_index_lookups.push(
                cond.clone()
                    * (cells.call_index.expression.clone()
                        - cells.prev_call_index.expression.clone()),
            );
            // for same call_index, index must be great than or equal to prev_index
            locals_index_lookups.push(
                cond * (1.expr()
                    - delt_call_index * cells.delta_invert_call_index.expression.clone())
                    * (cells.index.expression.clone() - cells.prev_index.expression.clone()),
            );

            // empty op
            constraints.push((
                "empty op counter",
                cells.is_empty.expression.clone()
                    * (cells.counter.expression.clone() - cells.prev_counter.expression.clone()),
            ));
        }
    }

    // assign each cell of the locals operation, return assigned cell for counter
    pub fn assign(
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
                .call_index
                .assign(region, offset, Some(op.call_index.0))?;

            self.config
                .cells
                .index
                .assign(region, offset, Some(op.address.0))?;

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

            self.config.cells.call_index.assign_equality(
                region,
                offset,
                op.call_index.1.clone().ok_or_else(|| {
                    error!("call_index assigned cell is None");
                    Error::Synthesis
                })?,
                "call_index",
            )?;

            self.config.cells.index.assign_equality(
                region,
                offset,
                op.address.1.clone().ok_or_else(|| {
                    error!("address assigned cell is None");
                    Error::Synthesis
                })?,
                "address",
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

        let (prev_call_index, prev_index) = match prev_op {
            None => (F::zero(), F::zero()),
            Some(v) => (v.call_index.0, v.address.0),
        };
        self.config.cells.delta_invert_call_index.assign(
            region,
            offset,
            op.call_index.0.delta_invert(prev_call_index),
        )?;
        self.config.cells.delta_invert_index.assign(
            region,
            offset,
            op.address.0.delta_invert(prev_index),
        )?;

        let is_empty = if is_empty { F::one() } else { F::zero() };
        self.config
            .cells
            .is_empty
            .assign(region, offset, Some(is_empty))?;

        Ok(assigned)
    }
}
