// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookupTable, bitwise_lookup_table::BitwiseLookupTable,
    bytecode_lookup_table::BytecodeLookupTable, call_lookup_table::CallLookupTable,
    rw_table::RWTable, LookupsWithCondition,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::utilities::*;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
// use logger::prelude::*;
use movelang::value::NUM_OF_BYTES_U128;
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STEP_CHIP_WIDTH: usize = 10;
pub const STEP_HEIGHT: usize = 11; //todo: calculate step height automatically
pub const NUM_OF_STEP_STATE: usize = 11; //pc, stack_size, call_index, locals_index, gc, auxiliary_1, auxiliary_2, auxiliary_3, auxiliary_4, module_index, func_index
pub const MAX_OPERANDS_PER_STEP: usize = 3; //value_a, value_b, value_c
pub const MAX_NUM_OF_ARGUMENTS_OR_STRUCT_FIELDS: usize = 10; //max(method_arguments#, struct_fields#)
                                                             //todo: dynamic configure according to the real argument number and struct fields

#[derive(Clone, Debug)]
pub struct StepChipCells<F: FieldExt> {
    pub pc: Cell<F>,
    pub stack_size: Cell<F>,
    pub call_index: Cell<F>,
    pub locals_index: Cell<F>,
    pub gc: Cell<F>,
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub auxiliary_1: Cell<F>,
    pub auxiliary_2: Cell<F>,
    pub auxiliary_3: Cell<F>,
    pub auxiliary_4: Cell<F>,

    pub conditions: Vec<Cell<F>>,

    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,

    pub args_or_fields: Vec<Cell<F>>,
    pub args_or_fields_mask: Vec<Cell<F>>,

    pub bytes: Vec<Cell<F>>,
    pub bytes_operand_1: Vec<Cell<F>>,
    pub bytes_operand_2: Vec<Cell<F>>,

    pub next_pc: Cell<F>,
    pub next_stack_size: Cell<F>,
    pub next_call_index: Cell<F>,
    pub next_locals_index: Cell<F>,
    pub next_gc: Cell<F>,
    pub next_module_index: Cell<F>,
    pub next_function_index: Cell<F>,
    pub next_auxiliary_1: Cell<F>,
    pub next_auxiliary_2: Cell<F>,
    pub next_auxiliary_3: Cell<F>,
    pub next_auxiliary_4: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StepConfig<F: FieldExt> {
    pub advices: [Column<Advice>; STEP_CHIP_WIDTH],
    pub cells: StepChipCells<F>,
    pub s_step: Selector,
}

pub struct StepChip<F: FieldExt> {
    pub config: StepConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for StepChip<F> {
    type Config = StepConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> StepChip<F> {
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
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        rw_table: &RWTable,
        bytecode_table: &BytecodeLookupTable,
        calls_table: &CallLookupTable,
        arith_op_table: &ArithOpLookupTable,
        bitwise_table: &BitwiseLookupTable,
    ) -> <Self as Chip<F>>::Config {
        // query advice for each state of the step
        let cell_amount = NUM_OF_STEP_STATE
            + MAX_OPERANDS_PER_STEP
            + Opcode::total_numbers()
            + MAX_NUM_OF_ARGUMENTS_OR_STRUCT_FIELDS * 2
            + NUM_OF_BYTES_U128 * 3;
        let mut cells = VecDeque::with_capacity(cell_amount);
        meta.create_gate("step", |meta| {
            for i in 0..cell_amount {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH;
                cells.push_back(Cell::new(meta, advices[column_index], rotation as i32))
            }

            // remember cells of the states of the next step
            for i in 0..NUM_OF_STEP_STATE {
                let column_index = i % STEP_CHIP_WIDTH;
                let rotation = i / STEP_CHIP_WIDTH + STEP_HEIGHT;
                cells.push_back(Cell::new(meta, advices[column_index], rotation as i32))
            }
            vec![Expression::Constant(F::zero())]
        });

        let cells = StepChipCells {
            pc: cells.pop_front().unwrap(),
            stack_size: cells.pop_front().unwrap(),
            call_index: cells.pop_front().unwrap(),
            locals_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            module_index: cells.pop_front().unwrap(),
            function_index: cells.pop_front().unwrap(),
            auxiliary_1: cells.pop_front().unwrap(),
            auxiliary_2: cells.pop_front().unwrap(),
            auxiliary_3: cells.pop_front().unwrap(),
            auxiliary_4: cells.pop_front().unwrap(),

            conditions: cells.drain(0..Opcode::total_numbers()).collect(),

            value_a: cells.pop_front().unwrap(),
            value_b: cells.pop_front().unwrap(),
            value_c: cells.pop_front().unwrap(),

            args_or_fields: cells
                .drain(0..MAX_NUM_OF_ARGUMENTS_OR_STRUCT_FIELDS)
                .collect(),
            args_or_fields_mask: cells
                .drain(0..MAX_NUM_OF_ARGUMENTS_OR_STRUCT_FIELDS)
                .collect(),

            bytes: cells.drain(0..NUM_OF_BYTES_U128).collect(),
            bytes_operand_1: cells.drain(0..NUM_OF_BYTES_U128).collect(),
            bytes_operand_2: cells.drain(0..NUM_OF_BYTES_U128).collect(),

            next_pc: cells.pop_front().unwrap(),
            next_stack_size: cells.pop_front().unwrap(),
            next_call_index: cells.pop_front().unwrap(),
            next_locals_index: cells.pop_front().unwrap(),
            next_gc: cells.pop_front().unwrap(),
            next_module_index: cells.pop_front().unwrap(),
            next_function_index: cells.pop_front().unwrap(),
            next_auxiliary_1: cells.pop_front().unwrap(),
            next_auxiliary_2: cells.pop_front().unwrap(),
            next_auxiliary_3: cells.pop_front().unwrap(),
            next_auxiliary_4: cells.pop_front().unwrap(),
        };

        // enable equality for gc column, because we will copy last gc cell to memory chip.
        meta.enable_equality(cells.gc.column);

        // config each execution path of the step
        let mut constraints = Vec::new();
        let mut lookups = LookupsWithCondition::new();
        StepChip::constrain_step_conditions(&cells, &mut constraints);
        Opcode::iter().for_each(|opcode| opcode.configure(&cells, &mut constraints, &mut lookups));

        let s_step = meta.complex_selector();

        // for (i, constraint) in constraints.iter().enumerate() {
        //     debug!("constraint {}, {:?}", i, constraint);
        // }
        meta.create_gate("constrain step", |meta| {
            let s_step = meta.query_selector(s_step);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, s_step.clone() * constraint))
        });

        for (lookup, cond) in lookups.rw_lookups {
            meta.lookup_any(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.gc * cond.clone(),
                        meta.query_advice(rw_table.gc_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.rw_target * cond.clone(),
                        meta.query_advice(rw_table.rw_target_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.rw * cond.clone(),
                        meta.query_advice(rw_table.rw_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.call_index * cond.clone(),
                        meta.query_advice(rw_table.call_index_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.address * cond.clone(),
                        meta.query_advice(rw_table.address_column, Rotation::cur()),
                    ),
                    (
                        s_step * lookup.value * cond,
                        meta.query_advice(rw_table.value_column, Rotation::cur()),
                    ),
                ]
            });
        }

        for (lookup, cond) in lookups.bytecode_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.module_index * cond.clone(),
                        bytecode_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index * cond.clone(),
                        bytecode_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc * cond.clone(),
                        bytecode_table.pc_column,
                    ),
                    (
                        s_step.clone() * lookup.opcode * cond.clone(),
                        bytecode_table.opcode_column,
                    ),
                    (
                        s_step * lookup.operand * cond.clone(),
                        bytecode_table.operand_column,
                    ),
                ]
            });
        }

        for (lookup, cond) in lookups.call_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.type_ * cond.clone(),
                        calls_table.type_column,
                    ),
                    (
                        s_step.clone() * lookup.module_index * cond.clone(),
                        calls_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index * cond.clone(),
                        calls_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc * cond.clone(),
                        calls_table.pc_column,
                    ),
                    (
                        s_step.clone() * lookup.next_module_index * cond.clone(),
                        calls_table.callee_module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.next_function_index * cond.clone(),
                        calls_table.callee_function_index_column,
                    ),
                    (s_step * lookup.next_pc * cond, calls_table.next_pc_column),
                ]
            });
        }

        for (lookup, cond) in lookups.arith_op_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.module_index * cond.clone(),
                        arith_op_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index * cond.clone(),
                        arith_op_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc * cond.clone(),
                        arith_op_table.pc_column,
                    ),
                    (
                        s_step * lookup.num_of_bytes * cond,
                        arith_op_table.num_of_bytes_column,
                    ),
                ]
            });
        }

        // for (i, item) in lookups.bitwise_lookups.iter().enumerate() {
        //      debug!("bitwise lookup {}, {:?}", i, item);
        // }
        for (lookup, cond) in lookups.bitwise_lookups {
            meta.lookup(|meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.opcode * cond.clone(),
                        bitwise_table.opcode_column,
                    ),
                    (
                        s_step.clone() * lookup.value_1 * cond.clone(),
                        bitwise_table.value_1_column,
                    ),
                    (
                        s_step.clone() * lookup.value_2 * cond.clone(),
                        bitwise_table.value_2_column,
                    ),
                    (
                        s_step * lookup.result * cond.clone(),
                        bitwise_table.result_column,
                    ),
                ]
            });
        }
        StepConfig {
            advices,
            cells,
            s_step,
        }
    }

    // step condition must be 1 or 0, and sum of all conditions must be 1
    fn constrain_step_conditions(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
    ) {
        let one = Expression::Constant(F::one());

        let mut zero_or_one = cells
            .conditions
            .iter()
            .map(|cell| {
                (
                    "zero or one",
                    (cell.expression.clone() - one.clone()) * cell.expression.clone(),
                )
            })
            .collect::<Vec<_>>();
        constraints.append(&mut zero_or_one);

        let sum_to_one = cells
            .conditions
            .iter()
            .fold(one, |acc, cell| acc - cell.expression.clone());
        constraints.push(("sum to one", sum_to_one));
    }

    // assign each cell of the step, return assigned cell for gc
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
    ) -> Result<Option<AssignedCell<F, F>>, Error> {
        // assign step states
        self.config
            .cells
            .pc
            .assign(region, offset, Some(F::from(step.pc as u64)))?;
        self.config.cells.stack_size.assign(
            region,
            offset,
            Some(F::from(step.stack_size as u64)),
        )?;
        self.config.cells.call_index.assign(
            region,
            offset,
            Some(F::from(step.call_index as u64)),
        )?;
        self.config.cells.locals_index.assign(
            region,
            offset,
            Some(F::from(step.locals_index as u64)),
        )?;
        let gc_assigned_cell =
            self.config
                .cells
                .gc
                .assign(region, offset, Some(F::from(step.gc as u64)))?;
        self.config.cells.module_index.assign(
            region,
            offset,
            Some(F::from(step.module_index as u64)),
        )?;
        self.config.cells.function_index.assign(
            region,
            offset,
            Some(F::from(step.function_index as u64)),
        )?;

        // assign conditions
        self.config
            .cells
            .conditions
            .iter()
            .enumerate()
            .for_each(|(index, cell)| {
                let condition = if step.opcode.index() == index {
                    F::one()
                } else {
                    F::zero()
                };
                let _assigned = cell.assign(region, offset, Some(condition));
            });

        // assign other cells for the step
        step.opcode
            .assign(region, offset, step, rw_operations, &self.config.cells)?;

        Ok(Some(gc_assigned_cell))
    }
}
