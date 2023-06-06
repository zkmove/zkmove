// Copyright (c) zkMove Authors

use crate::chips::execution_chip::param::MAX_ADDRESS_EXT_LENGTH;
use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{ConvertedRWOperation, RW};
use crate::witness::CircuitConfig;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const STACK_OP_CHIP_WIDTH: usize = 28;

#[derive(Clone, Debug)]
pub struct StackOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of stack operations
    pub address: Cell<F>,
    pub address_ext_0: Cell<F>,
    pub addr_ext_bytes: Vec<Cell<F>>, // byte set for addr_ext_0
    pub address_ext_1: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub value_ext: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not
    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same locals
    pub delta_invert_address: Cell<F>,
    pub delta_invert_addr_ext_0: Cell<F>,
    pub delta_invert_addr_ext_bytes: Vec<Cell<F>>,
    pub delta_invert_addr_ext_1: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_address_ext_0: Cell<F>,
    pub prev_addr_ext_bytes: Vec<Cell<F>>, // byte set for prev_address_ext_0
    pub prev_address_ext_1: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_value_ext: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct StackOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: StackOpCells<F>,
    pub s_first_stack_op: Selector,
    pub s_stack_op: Selector,
    stack_address_table: TableColumn,
    addr_ext_0_table: TableColumn,
    addr_ext_1_table: TableColumn,
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
        let stack_address_table = meta.lookup_table_column();
        let addr_ext_0_table = meta.lookup_table_column();
        let addr_ext_1_table = meta.lookup_table_column();

        let mut cells = VecDeque::with_capacity(STACK_OP_CHIP_WIDTH * 2);
        meta.create_gate("stack op chip", |meta| {
            for i in 0..STACK_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op, without delta_invert cells
            for i in 0..(STACK_OP_CHIP_WIDTH - 3) {
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
            address_ext_0: cells.pop_front().unwrap(),
            addr_ext_bytes: {
                let mut vec = Vec::new();
                for _i in 0..MAX_ADDRESS_EXT_LENGTH {
                    vec.push(cells.pop_front().unwrap());
                }
                vec
            },
            address_ext_1: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            value_ext: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_address: cells.pop_front().unwrap(),
            delta_invert_addr_ext_0: cells.pop_front().unwrap(),
            delta_invert_addr_ext_bytes: {
                let mut vec = Vec::new();
                for _i in 0..MAX_ADDRESS_EXT_LENGTH {
                    vec.push(cells.pop_front().unwrap());
                }
                vec
            },
            delta_invert_addr_ext_1: cells.pop_front().unwrap(),

            prev_counter: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_address: cells.pop_front().unwrap(),
            prev_address_ext_0: cells.pop_front().unwrap(),
            prev_addr_ext_bytes: {
                let mut vec = Vec::new();
                for _i in 0..MAX_ADDRESS_EXT_LENGTH {
                    vec.push(cells.pop_front().unwrap());
                }
                vec
            },
            prev_address_ext_1: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_value_ext: cells.pop_front().unwrap(),
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
            &addr_ext_0_table,
            &addr_ext_1_table,
        );

        let s_stack_op = meta.complex_selector();
        Self::config_stack_op(
            meta,
            s_stack_op,
            &cells,
            false,
            gc_table,
            &stack_address_table,
            &addr_ext_0_table,
            &addr_ext_1_table,
        );

        StackOpChipConfig {
            advices,
            cells,
            s_first_stack_op,
            s_stack_op,
            stack_address_table,
            addr_ext_0_table,
            addr_ext_1_table,
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
        addr_ext_0_table: &TableColumn,
        addr_ext_1_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        let mut stack_address_lookups = Vec::new();
        let mut addr_ext_0_lookups = Vec::new();
        let mut addr_ext_1_lookups = Vec::new();

        Self::constrain_stack_op(
            cells,
            &mut constraints,
            is_first_op,
            &mut gc_lookups,
            &mut stack_address_lookups,
            &mut addr_ext_0_lookups,
            &mut addr_ext_1_lookups,
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

        for lookup in addr_ext_0_lookups {
            meta.lookup("stack address ext_0", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext_0_table)]
            });
        }

        for lookup in addr_ext_1_lookups {
            meta.lookup("stack address ext_1", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext_1_table)]
            });
        }
    }

    fn constrain_stack_op(
        cells: &StackOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
        stack_address_lookups: &mut Vec<Expression<F>>,
        addr_ext_0_lookups: &mut Vec<Expression<F>>,
        addr_ext_1_lookups: &mut Vec<Expression<F>>,
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
                "stack counter",
                cond.clone()
                    * (cells.counter.expression.clone()
                        - cells.prev_counter.expression.clone()
                        - 1.expr()),
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "stack rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1.expr()),
            ));
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "stack read op: value",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read.clone(),
            ));
            constraints.push((
                "stack read op: value_ext",
                cond.clone()
                    * (cells.value_ext.expression.clone()
                        - cells.prev_value_ext.expression.clone())
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
                        - 1.expr()),
            ));
            let delt_addr_ext_0 = cells.address_ext_0.expression.clone()
                - cells.prev_address_ext_0.expression.clone();
            constraints.push((
                "stack_delt_invert_address_ext_0",
                cond.clone()
                    * delt_addr_ext_0.clone()
                    * (delt_addr_ext_0.clone() * cells.delta_invert_addr_ext_0.expression.clone()
                        - 1.expr()),
            ));
            let delt_addr_ext_1 = cells.address_ext_1.expression.clone()
                - cells.prev_address_ext_1.expression.clone();
            constraints.push((
                "stack_delt_invert_address_ext_1",
                cond.clone()
                    * delt_addr_ext_1.clone()
                    * (delt_addr_ext_1.clone() * cells.delta_invert_addr_ext_1.expression.clone()
                        - 1.expr()),
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
            //            address_ext_0 != prev_address_ext_0
            //         then rw == Write
            constraints.push((
                "stack_addr_ext_0_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * (1.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * delt_addr_ext_0.clone(),
            ));
            // Case C: if address == prev_address and
            //            address_ext_0 == prev_address_ext_0
            //            address_ext_1 != prev_address_ext_1
            //         then rw == Write
            constraints.push((
                "stack_addr_ext_1_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * (1.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_0.clone()
                            * cells.delta_invert_addr_ext_0.expression.clone())
                    * delt_addr_ext_1.clone(),
            ));

            // for ops with same address, gc must be greater than prev_gc
            // lookup gc_table when address is same with previous
            gc_lookups.push(
                cond.clone()
                    * (1.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_0.clone()
                            * cells.delta_invert_addr_ext_0.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_1.clone()
                            * cells.delta_invert_addr_ext_1.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // address validation check
            // stack address index must be less than max_stack_size(EVAL_STACK_SIZE)
            stack_address_lookups.push(cond.clone() * cells.address.expression.clone());
            // address_ext_0 must be less than max_locals_size
            for i in 0..MAX_ADDRESS_EXT_LENGTH {
                addr_ext_0_lookups.push(cond.clone() * cells.addr_ext_bytes[i].expression.clone());
            }
            // addr_ext_1 must be less than max_locals_size
            addr_ext_1_lookups.push(cond.clone() * cells.address_ext_1.expression.clone());

            // addr_ext_bytes validation
            let bytes = FieldBytes16bit::from(cells.addr_ext_bytes.clone()).expr();
            let constraint = cond.clone() * (cells.address_ext_0.expression.clone() - bytes);
            constraints.push(("addr_ext_bytes check", constraint));

            // address monotonic increment
            // Case A: address must be great than or equal to prev_address
            stack_address_lookups.push(cond.clone() * delt_address.clone());

            // Case B: if same address,
            //            addr_ext_0 must be great than or equal to prev_addr_ext_0
            for i in (0..MAX_ADDRESS_EXT_LENGTH).rev() {
                let delta = cells.addr_ext_bytes[i].expression.clone()
                    - cells.prev_addr_ext_bytes[i].expression.clone();
                let init = cond.clone()
                    * (1.expr()
                        - delt_address.clone() * (cells.delta_invert_address.expression.clone()))
                    * delta;
                let val = ((i + 1)..MAX_ADDRESS_EXT_LENGTH)
                    .rev()
                    .map(|j| {
                        1.expr()
                            - (cells.addr_ext_bytes[j].expression.clone()
                                - cells.prev_addr_ext_bytes[j].expression.clone())
                                * cells.delta_invert_addr_ext_bytes[j].expression.clone()
                    })
                    .fold(init, |acc, cell| acc * cell);

                addr_ext_0_lookups.push(val);
            }

            // Case C: if same address/addr_ext_0,
            //            addr_ext_1 must be great than or equal to prev_addr_ext_1
            addr_ext_1_lookups.push(
                cond * (1.expr() - delt_address * cells.delta_invert_address.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_0 * cells.delta_invert_addr_ext_0.expression.clone())
                    * delt_addr_ext_1,
            );

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

        if is_empty {
            self.config.cells.gc.assign(region, offset, Some(op.gc.0))?;

            self.config.cells.rw.assign(region, offset, Some(op.rw.0))?;

            self.config
                .cells
                .address
                .assign(region, offset, Some(op.address.0))?;

            self.config
                .cells
                .address_ext_0
                .assign(region, offset, Some(op.address_ext_0.0))?;
            // assign addr_ext_0_bytes
            assign_to_cells_bit16(
                region,
                offset,
                Some(op.address_ext_0.0),
                &self.config.cells.addr_ext_bytes,
            )?;

            self.config
                .cells
                .address_ext_1
                .assign(region, offset, Some(op.address_ext_1.0))?;

            self.config.cells.value.assign(region, offset, op.value.0)?;

            self.config
                .cells
                .value_ext
                .assign(region, offset, op.value_ext.0)?;

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

            self.config.cells.address_ext_0.assign_equality(
                region,
                offset,
                op.address_ext_0.1.clone().ok_or_else(|| {
                    error!("address_ext_0 assigned cell is None");
                    Error::Synthesis
                })?,
                "address_ext_0",
            )?;
            // assign addr_ext_0_bytes
            assign_to_cells_bit16(
                region,
                offset,
                Some(op.address_ext_0.0),
                &self.config.cells.addr_ext_bytes,
            )?;

            self.config.cells.address_ext_1.assign_equality(
                region,
                offset,
                op.address_ext_1.1.clone().ok_or_else(|| {
                    error!("address_ext_1 assigned cell is None");
                    Error::Synthesis
                })?,
                "address_ext_1",
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

            self.config.cells.value_ext.assign_equality(
                region,
                offset,
                op.value_ext.1.clone().ok_or_else(|| {
                    error!("value_ext assigned cell is None");
                    Error::Synthesis
                })?,
                "value_ext",
            )?;

            let (prev_address, prev_addr_ext_0, pre_addr_ext_1) = match prev_op {
                None => (F::zero(), F::zero(), F::zero()),
                Some(v) => (v.address.0, v.address_ext_0.0, v.address_ext_1.0),
            };
            self.config.cells.delta_invert_address.assign(
                region,
                offset,
                op.address.0.delta_invert(prev_address),
            )?;
            self.config.cells.delta_invert_addr_ext_0.assign(
                region,
                offset,
                op.address_ext_0.0.delta_invert(prev_addr_ext_0),
            )?;
            assign_invert_to_cells_bit16(
                region,
                offset,
                Some(op.address_ext_0.0),
                Some(prev_addr_ext_0),
                &self.config.cells.delta_invert_addr_ext_bytes,
            )?;
            self.config.cells.delta_invert_addr_ext_1.assign(
                region,
                offset,
                op.address_ext_1.0.delta_invert(pre_addr_ext_1),
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
        circuit_config: &CircuitConfig,
        stack_ops: Vec<ConvertedRWOperation<F>>,
        stack_ops_num: usize,
    ) -> Option<AssignedCell<F, F>> {
        let mut last_stack_counter: Option<AssignedCell<F, F>> = None;

        if !stack_ops.is_empty() || stack_ops_num > 0 {
            layouter
                .assign_region(
                    || "stack operations",
                    |mut region: Region<'_, F>| {
                        let mut prev_op = None;
                        let mut counter = 0;
                        for (index, op) in stack_ops.iter().enumerate() {
                            counter = index + 1;
                            let assigned_counter = if index == 0 {
                                self.config.s_first_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, false)?
                            } else {
                                self.config.s_stack_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, false)?
                            };
                            if counter == stack_ops.len() {
                                last_stack_counter = Some(assigned_counter);
                            }
                            prev_op = Some(op.clone());
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
                                        None,
                                        true,
                                    )?
                                } else {
                                    self.config.s_stack_op.enable(&mut region, index)?;
                                    self.assign_cell(
                                        &mut region,
                                        index,
                                        &ConvertedRWOperation::empty(),
                                        counter,
                                        prev_op,
                                        true,
                                    )?
                                };
                                last_stack_counter = Some(assigned_counter);
                                prev_op = Some(ConvertedRWOperation::empty());
                            }
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
                    .fold(Ok(()), |acc, res| acc.and(res))
            },
        )?;
        Ok(())
    }

    // assign tables of the locals varible
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
            "addr_ext_0_table",
            self.config.addr_ext_0_table,
            circuit_config.word_size,
        )?;
        self.assign_index_table(
            layouter,
            "addr_ext_1_table",
            self.config.addr_ext_1_table,
            circuit_config.word_size,
        )?;
        Ok(())
    }
}
