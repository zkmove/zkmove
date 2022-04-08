// Copyright (c) zkMove Authors

use crate::value::Value;
use crate::vm_circuit::chips::lookup_tables::{RWTable, RWTarget};
use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::{LocalsOp, RW};
use crate::vm_circuit::memory_circuit::MEM_CIRCUIT_WIDTH;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const LOCALS_OP_CHIP_WIDTH: usize = 5;

#[derive(Clone, Debug)]
pub struct LocalsOpCells<F: FieldExt> {
    pub call_index: Cell<F>,
    pub index: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,

    pub prev_call_index: Cell<F>,
    pub prev_index: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct LocalsOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CIRCUIT_WIDTH],
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
        advices: [Column<Advice>; MEM_CIRCUIT_WIDTH],
        rw_table: &RWTable,
    ) -> <Self as Chip<F>>::Config {
        let mut cells = VecDeque::with_capacity(LOCALS_OP_CHIP_WIDTH * 2);
        meta.create_gate("locals op chip", |meta| {
            for i in 0..LOCALS_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op
            for i in 0..LOCALS_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = LocalsOpCells {
            call_index: cells.pop_front().unwrap(),
            index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            prev_call_index: cells.pop_front().unwrap(),
            prev_index: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
        };

        let s_first_locals_op = meta.complex_selector();
        Self::config_locals_op(meta, s_first_locals_op, &cells, rw_table, true);

        let s_locals_op = meta.complex_selector();
        Self::config_locals_op(meta, s_locals_op, &cells, rw_table, false);

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
        rw_table: &RWTable,
        is_first_op: bool,
    ) {
        let mut constraints = Vec::new();
        Self::constrain_locals_op(&cells, &mut constraints, is_first_op);

        meta.create_gate("constrain locals op", |meta| {
            let selector = meta.query_selector(selector);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, selector.clone() * constraint))
        });

        meta.lookup(|meta| {
            let selector = meta.query_selector(selector);
            vec![
                (
                    selector.clone() * cells.gc.expression.clone(),
                    rw_table.gc_column,
                ),
                (
                    selector.clone() * (RWTarget::Locals as u64).expr(),
                    rw_table.rw_target_column,
                ),
                (
                    selector.clone() * cells.rw.expression.clone(),
                    rw_table.rw_column,
                ),
                (
                    selector.clone() * cells.call_index.expression.clone(),
                    rw_table.call_index_column,
                ),
                (
                    selector.clone() * cells.index.expression.clone(),
                    rw_table.address_column,
                ),
                (
                    selector * cells.value.expression.clone(),
                    rw_table.value_column,
                ),
            ]
        });
    }

    fn constrain_locals_op(
        cells: &LocalsOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
    ) {
        if is_first {
            // for the first op: rw == Write
            // note, ether call_index or index may NOT be 0
            constraints.push((
                "first locals op",
                cells.rw.expression.clone() - (RW::WRITE as u64).expr(),
            ));
        } else {
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                (cells.value.expression.clone() - cells.prev_value.expression.clone()) * is_read,
            ));

            // if index != prev_index then rw == Write
            let delt_index = cells.index.expression.clone() - cells.prev_index.expression.clone();
            constraints.push((
                "index",
                (cells.rw.expression.clone() - (RW::WRITE as u64).expr()) * delt_index,
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cells.rw.expression.clone() * (cells.rw.expression.clone() - 1.expr()),
            ));

            // todo: index must be great than or equal to prev_index
            // todo: index must be less than MAX_LOCALS_SIZE
            // todo: gc must be great than prev_gc
        }
    }

    // assign each cell of the locals operation
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op: &LocalsOp<F>,
    ) -> Result<(), Error> {
        self.config
            .cells
            .gc
            .assign(region, offset, Some(F::from(op.gc as u64)))?;

        self.config
            .cells
            .rw
            .assign(region, offset, Some(F::from(op.rw.clone() as u64)))?;

        self.config
            .cells
            .call_index
            .assign(region, offset, Some(F::from(op.call_index as u64)))?;

        self.config
            .cells
            .index
            .assign(region, offset, Some(F::from(op.index as u64)))?;

        let field = match op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => op.value.value(),
        };

        self.config.cells.value.assign(region, offset, field)?;

        Ok(())
    }
}
