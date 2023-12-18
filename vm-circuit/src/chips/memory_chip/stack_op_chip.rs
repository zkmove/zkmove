// Copyright (c) zkMove Authors

use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{ConvertedRWOperation, RW};
use crate::witness::CircuitConfig;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;
use types::Field;

pub const STACK_OP_CHIP_WIDTH: usize = 9;

#[derive(Clone, Debug)]
pub struct StackOpCells<F: Field> {
    pub counter: Cell<F>, // the total number of stack operations
    pub address: Cell<F>,
    pub address_ext: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not
    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same locals
    pub delta_invert_address: Cell<F>,
    pub delta_invert_addr_ext: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_address_ext: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StackOpChipConfig<F: Field> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: StackOpCells<F>,
    pub s_first_stack_op: Selector,
    pub s_stack_op: Selector,
    stack_address_table: TableColumn,
    addr_ext_table: TableColumn,
}

pub struct StackOpChip<F: Field> {
    pub config: StackOpChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for StackOpChip<F> {
    type Config = StackOpChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> StackOpChip<F> {
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
        let stack_address_table = meta.lookup_table_column();
        let addr_ext_table = meta.lookup_table_column();

        let mut cells = VecDeque::with_capacity(STACK_OP_CHIP_WIDTH * 2);
        meta.create_gate("stack op chip", |meta| {
            for i in 0..STACK_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op, without delta_invert cells
            for i in 0..(STACK_OP_CHIP_WIDTH - 2) {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::ZERO)]
        });

        let cells = StackOpCells {
            counter: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            address: cells.pop_front().unwrap(),
            address_ext: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_address: cells.pop_front().unwrap(),
            delta_invert_addr_ext: cells.pop_front().unwrap(),

            prev_counter: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
            prev_address_ext: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_is_empty: cells.pop_front().unwrap(),
        };

        let s_first_stack_op = meta.complex_selector();
        Self::config_stack_op(
            meta,
            s_first_stack_op,
            &cells,
            true,
            gc_table,
            &stack_address_table,
            &addr_ext_table,
        );

        let s_stack_op = meta.complex_selector();
        Self::config_stack_op(
            meta,
            s_stack_op,
            &cells,
            false,
            gc_table,
            &stack_address_table,
            &addr_ext_table,
        );

        StackOpChipConfig {
            advices,
            cells,
            s_first_stack_op,
            s_stack_op,
            stack_address_table,
            addr_ext_table,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn config_stack_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &StackOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
        stack_address_table: &TableColumn,
        addr_ext_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        let mut stack_address_lookups = Vec::new();
        let mut addr_ext_lookups = Vec::new();

        Self::constrain_stack_op(
            cells,
            &mut constraints,
            is_first_op,
            &mut gc_lookups,
            &mut stack_address_lookups,
            &mut addr_ext_lookups,
        );

        meta.create_gate("constrain stack op", |meta| {
            let selector = meta.query_selector(selector);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, selector.clone() * constraint))
        });

        for lookup in gc_lookups {
            meta.lookup("stack gc", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *gc_table)]
            });
        }

        for lookup in stack_address_lookups {
            meta.lookup("stack address", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *stack_address_table)]
            });
        }

        for lookup in addr_ext_lookups {
            meta.lookup("stack address ext_0", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext_table)]
            });
        }
    }

    fn constrain_stack_op(
        cells: &StackOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
        stack_address_lookups: &mut Vec<Expression<F>>,
        //addr_ext_lookups: &mut <Expression<F>>,
        _addr_ext_lookups: &mut [Expression<F>],
    ) {
        constraints.push((
            "is_empty is bool",
            (cells.is_empty.expression.clone() - 1u64.expr()) * cells.is_empty.expression.clone(),
        ));
        let cond = 1u64.expr() - cells.is_empty.expression.clone();

        if is_first {
            // for the first op: counter == 1, address == 0, rw == Write
            constraints.push((
                "first stack op",
                cond.clone() * (cells.counter.expression.clone() - 1u64.expr()),
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
                "stack counter",
                cond.clone()
                    * (cells.counter.expression.clone()
                        - cells.prev_counter.expression.clone()
                        - 1u64.expr()),
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "stack rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1u64.expr()),
            ));
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "stack read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // constrain delta_invert: (a - b) * inverse(a - b) must be 1 or 0
            let delt_address =
                cells.address.expression.clone() - cells.prev_address.expression.clone();
            constraints.push((
                "stack_delt_invert_address",
                cond.clone()
                    * delt_address.clone()
                    * (delt_address.clone() * cells.delta_invert_address.expression.clone()
                        - 1u64.expr()),
            ));
            let delt_addr_ext =
                cells.address_ext.expression.clone() - cells.prev_address_ext.expression.clone();
            constraints.push((
                "stack_delt_invert_address_ext",
                cond.clone()
                    * delt_addr_ext.clone()
                    * (delt_addr_ext.clone() * cells.delta_invert_addr_ext.expression.clone()
                        - 1u64.expr()),
            ));

            // address change, then rw must be Write
            // Case A: if address != prev_address
            //         then rw == Write
            constraints.push((
                "stack_address",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * delt_address.clone(),
            ));
            // Case B: if address == prev_address and
            //            address_ext != prev_address_ext
            //         then rw == Write
            constraints.push((
                "stack_addr_ext_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * (1u64.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * delt_addr_ext.clone(),
            ));

            // for ops with same address, gc must be greater than prev_gc
            // lookup gc_table when address is same with previous
            gc_lookups.push(
                cond.clone()
                    * (1u64.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * (1u64.expr()
                        - delt_addr_ext * cells.delta_invert_addr_ext.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // address validation check
            // stack address index must be less than max_stack_size(EVAL_STACK_SIZE)
            stack_address_lookups.push(cond.clone() * cells.address.expression.clone());
            // address_ext must be less than max_locals_size
            // TODO. address extend validation
            // addr_ext_lookups.push(cond.clone() * cells.address_ext.expression.clone());

            // address monotonic increment
            // Case A: address must be great than or equal to prev_address
            stack_address_lookups.push(cond * delt_address);

            // Case B: if same address,
            //            addr_ext must be great than or equal to prev_addr_ext
            // TODO. address extend validation
            // addr_ext_lookups.push(
            //     cond.clone()
            //         * (1u64.expr()
            //             - delt_address.clone() * cells.delta_invert_address.expression.clone())
            //         * delt_addr_ext.clone(),
            // );

            // empty op
            constraints.push((
                "stack empty op counter",
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
        prev_op: Option<ConvertedRWOperation<F>>,
        is_empty: bool,
    ) -> Result<AssignedCell<F, F>, Error> {
        let assigned =
            self.config
                .cells
                .counter
                .assign(region, offset, Some(F::from(counter as u64)))?; //fixme: how about if counter is great than max_u64?

        // if is_empty {
        //     self.config.cells.gc.assign(region, offset, Some(op.gc.0))?;
        //
        //     self.config.cells.rw.assign(region, offset, Some(op.rw.0))?;
        //
        //     self.config
        //         .cells
        //         .address
        //         .assign(region, offset, Some(op.address.0))?;
        //
        //     self.config
        //         .cells
        //         .address_ext
        //         .assign(region, offset, Some(op.address_ext.0))?;
        //
        //     self.config.cells.value.assign(region, offset, op.value.0)?;
        //
        //     self.config
        //         .cells
        //         .value_ext
        //         .assign(region, offset, op.value_ext.0)?;
        //
        //     self.config
        //         .cells
        //         .is_empty
        //         .assign(region, offset, Some(F::ONE))?;
        // } else
        {
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

            self.config.cells.address_ext.assign_equality(
                region,
                offset,
                op.address_ext.1.clone().ok_or_else(|| {
                    error!("address_ext assigned cell is None");
                    Error::Synthesis
                })?,
                "address_ext",
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

            let (prev_address, prev_addr_ext) = match prev_op {
                None => (F::ZERO, F::ZERO),
                Some(v) => (v.address.0, v.address_ext.0),
            };
            self.config.cells.delta_invert_address.assign(
                region,
                offset,
                op.address.0.delta_invert(prev_address),
            )?;
            self.config.cells.delta_invert_addr_ext.assign(
                region,
                offset,
                op.address_ext.0.delta_invert(prev_addr_ext),
            )?;

            self.config.cells.is_empty.assign(
                region,
                offset,
                Some(if is_empty { F::ONE } else { F::ZERO }),
            )?;
        }

        Ok(assigned)
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        circuit_config: &CircuitConfig,
        stack_ops: Vec<ConvertedRWOperation<F>>,
        real_stack_ops_len: usize,
    ) -> Option<AssignedCell<F, F>> {
        let mut last_stack_counter: Option<AssignedCell<F, F>> = None;

        if !stack_ops.is_empty() {
            layouter
                .assign_region(
                    || "stack operations",
                    |mut region: Region<'_, F>| {
                        let mut prev_op = None;
                        let mut counter = 0;
                        for (index, op) in stack_ops.iter().enumerate().take(real_stack_ops_len) {
                            counter = index + 1;
                            let assigned_counter = if index == 0 {
                                self.config.s_first_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, false)?
                            } else {
                                self.config.s_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, false)?
                            };
                            if counter == real_stack_ops_len {
                                last_stack_counter = Some(assigned_counter);
                            }
                            prev_op = Some(op.clone());
                        }

                        // If the number of stack ops is less than stack_ops_num set by user, fill with
                        // empty op. This happened when the execution path is not fixed, for example,
                        // if there is loop in the code.

                        for (index, op) in stack_ops.iter().enumerate().skip(real_stack_ops_len) {
                            let assigned_counter = if index == 0 {
                                self.config.s_first_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, true)?
                            } else {
                                self.config.s_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, true)?
                            };
                            last_stack_counter = Some(assigned_counter);
                            prev_op = Some(op.clone());
                        }
                        Ok(())
                    },
                )
                .ok()?;
        }
        self.assign_table(layouter, circuit_config).ok()?;

        last_stack_counter
    }

    // a special table with solo column and the value same as index.
    // which is to garantuee value is among [0, max].
    fn assign_index_table(
        &self,
        layouter: &mut impl Layouter<F>,
        table_name: &str,
        column: TableColumn,
        max_row: usize,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || format!("{:?}", table_name),
            |mut table_column| {
                (0..=max_row)
                    .map(|i| {
                        table_column.assign_cell(
                            || format!("stack_index_table[{}]", i),
                            column,
                            i,
                            || CircuitValue::known(F::from_u128(i as u128)),
                        )
                    })
                    .try_fold((), |_, res| res)
            },
        )?;
        Ok(())
    }

    // assign tables for stack op chip
    pub fn assign_table(
        &self,
        layouter: &mut impl Layouter<F>,
        circuit_config: &CircuitConfig,
    ) -> Result<(), Error> {
        self.assign_index_table(
            layouter,
            "stack_address_table",
            self.config.stack_address_table,
            circuit_config.max_stack_size,
        )?;
        self.assign_index_table(
            layouter,
            "addr_ext_table",
            self.config.addr_ext_table,
            circuit_config.word_size,
        )?;

        Ok(())
    }

    pub fn tables_height(circuit_config: &CircuitConfig) -> usize {
        let stack_address_table_height = circuit_config.max_stack_size + 1;
        let addr_ext_table = circuit_config.word_size + 1;

        stack_address_table_height.max(addr_ext_table)
    }
}
