// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode::Opcode;
use crate::vm_circuit::chips::lookup_tables::{RWTable, RWTarget};
use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, StackOp};
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

    pub next_gc: Cell<F>,
    pub next_rw: Cell<F>,
    pub next_address: Cell<F>,
    pub next_value: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StackOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CIRCUIT_WIDTH],
    pub cells: StackOpCells<F>,
    pub s_stack: Selector,
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
            for i in 0..(STACK_OP_CHIP_WIDTH * 2) {
                let column_index = i % STACK_OP_CHIP_WIDTH;
                let rotation = i / STACK_OP_CHIP_WIDTH;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = StackOpCells {
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            address: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            next_gc: cells.pop_front().unwrap(),
            next_rw: cells.pop_front().unwrap(),
            next_address: cells.pop_front().unwrap(),
            next_value: cells.pop_front().unwrap(),
        };

        let mut constraints = Vec::new();
        Self::constrain_stack_op(&cells, &mut constraints);
        // for (i, constraint) in constraints.iter().enumerate() {
        //     debug!("constraint {}, {:?}", i, constraint);
        // }

        let s_stack = meta.complex_selector();
        meta.create_gate("constrain stack op", |meta| {
            let s_stack = meta.query_selector(s_stack);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, s_stack.clone() * constraint))
        });

        meta.lookup(|meta| {
            let s_stack = meta.query_selector(s_stack);
            vec![
                (
                    s_stack.clone() * cells.gc.expression.clone(),
                    rw_table.gc_column,
                ),
                (
                    s_stack.clone() * (RWTarget::Stack as u64).expr(),
                    rw_table.rw_target_column,
                ),
                (
                    s_stack.clone() * cells.rw.expression.clone(),
                    rw_table.rw_column,
                ),
                (
                    s_stack.clone() * cells.address.expression.clone(),
                    rw_table.address_column,
                ),
                (
                    s_stack * cells.value.expression.clone(),
                    rw_table.value_column,
                ),
            ]
        });

        StackOpChipConfig {
            advices,
            cells,
            s_stack,
        }
    }

    fn constrain_stack_op(cells: &StackOpCells<F>, constraints: &mut Vec<(&str, Expression<F>)>) {
        // add constraints here
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
