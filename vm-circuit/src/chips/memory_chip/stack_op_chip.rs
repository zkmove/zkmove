// Copyright (c) zkMove Authors

use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{StackOp, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STACK_OP_CHIP_WIDTH: usize = 6;

#[derive(Clone, Debug)]
pub struct StackOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of stack operations
    pub address: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
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
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            prev_counter: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
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
                cond.clone() * (cells.rw.expression.clone() - (RW::WRITE as u64).expr()),
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

            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // if address != prev_address then rw == Write
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

            // for ops with same address, gc must be great than prev_gc
            gc_lookups.push(
                cond.clone()
                    * (1.expr() - delt_addr)
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
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op: &StackOp<F>,
        counter: usize,
        is_empty: bool,
    ) -> Result<AssignedCell<F, F>, Error> {
        let assigned =
            self.config
                .cells
                .counter
                .assign(region, offset, Some(F::from(counter as u64)))?; //fixme: how about if counter is great than max_u64?

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
            .address
            .assign(region, offset, Some(F::from(op.address as u64)))?;

        self.config
            .cells
            .value
            .assign(region, offset, op.value.value())?;

        let is_empty = if is_empty { F::one() } else { F::zero() };
        self.config
            .cells
            .is_empty
            .assign(region, offset, Some(is_empty))?;

        Ok(assigned)
    }
}
