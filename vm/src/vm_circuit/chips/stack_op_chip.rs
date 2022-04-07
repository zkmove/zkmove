// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::lookup_tables::{RWTable, RWTarget};
use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::{StackOp, RW};
use crate::vm_circuit::memory_circuit::MEM_CIRCUIT_WIDTH;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STACK_OP_CHIP_WIDTH: usize = 4;

#[derive(Clone, Debug)]
pub struct StackOpCells<F: FieldExt> {
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub address: Cell<F>,
    pub value: Cell<F>,

    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_value: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StackOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CIRCUIT_WIDTH],
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
        advices: [Column<Advice>; MEM_CIRCUIT_WIDTH],
        rw_table: &RWTable,
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
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            address: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
        };

        let s_first_stack_op = meta.complex_selector();
        Self::config_stack_op(meta, s_first_stack_op, &cells, rw_table, true);

        let s_stack_op = meta.complex_selector();
        Self::config_stack_op(meta, s_stack_op, &cells, rw_table, false);

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
        rw_table: &RWTable,
        is_first_op: bool,
    ) {
        let mut constraints = Vec::new();
        Self::constrain_stack_op(&cells, &mut constraints, is_first_op);

        meta.create_gate("constrain stack op", |meta| {
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
                    selector.clone() * (RWTarget::Stack as u64).expr(),
                    rw_table.rw_target_column,
                ),
                (
                    selector.clone() * cells.rw.expression.clone(),
                    rw_table.rw_column,
                ),
                (
                    selector.clone() * cells.address.expression.clone(),
                    rw_table.address_column,
                ),
                (
                    selector * cells.value.expression.clone(),
                    rw_table.value_column,
                ),
            ]
        });
    }

    fn constrain_stack_op(
        cells: &StackOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
    ) {
        if is_first {
            // for the first op: gc == 0, address == 0, rw == Write
            constraints.push(("first stack op", cells.address.expression.clone()));
            constraints.push((
                "first stack op",
                cells.rw.expression.clone() - (RW::WRITE as u64).expr(),
            ));
        } else {
            // 'address == prev_address' or 'address == prev_address + 1'
            let delt_addr =
                cells.address.expression.clone() - cells.prev_address.expression.clone();
            constraints.push((
                "address",
                delt_addr.clone() * (delt_addr.clone() - 1.expr()),
            ));

            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                (cells.value.expression.clone() - cells.prev_value.expression.clone()) * is_read,
            ));

            // if address != prev_address then rw == Write
            constraints.push((
                "address ",
                (cells.rw.expression.clone() - (RW::WRITE as u64).expr()) * delt_addr,
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cells.rw.expression.clone() * (cells.rw.expression.clone() - 1.expr()),
            ));

            // todo: address must be less than EVAL_STACK_SIZE
            // todo: gc must be great than prev_gc
        }
    }

    // assign each cell of the stack operation
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        op: &StackOp<F>,
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
            .address
            .assign(region, offset, Some(F::from(op.address as u64)))?;

        self.config
            .cells
            .value
            .assign(region, offset, op.value.value())?;

        Ok(())
    }
}
