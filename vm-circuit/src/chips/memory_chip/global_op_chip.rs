// Copyright (c) zkMove Authors

use crate::chips::execution_chip::param::MAX_ADDRESS_EXT_LENGTH;
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

pub const GLOBAL_OP_CHIP_WIDTH: usize = 30;

#[derive(Clone, Debug)]
pub struct GlobalOpCells<F: FieldExt> {
    pub counter: Cell<F>, // the total number of global rw operations
    pub address: Cell<F>,
    pub sd_index: Cell<F>, // struct definition index
    pub address_ext_0: Cell<F>,
    pub addr_ext_bytes: Vec<Cell<F>>, // byte set for addr_ext_0
    pub address_ext_1: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub value_ext: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not

    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same global address
    pub delta_invert_address: Cell<F>,
    pub delta_invert_sd_index: Cell<F>,
    pub delta_invert_addr_ext_0: Cell<F>,
    pub delta_invert_addr_ext_bytes: Vec<Cell<F>>,
    pub delta_invert_addr_ext_1: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_address: Cell<F>,
    pub prev_sd_index: Cell<F>,
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
pub struct GlobalOpChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: GlobalOpCells<F>,
    pub s_first_global_op: Selector,
    pub s_global_op: Selector,
    addr_ext_0_table: TableColumn,
    addr_ext_1_table: TableColumn,
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
            for i in 0..(GLOBAL_OP_CHIP_WIDTH - 4) {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = GlobalOpCells {
            counter: cells.pop_front().unwrap(),
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
            sd_index: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            value_ext: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_address: cells.pop_front().unwrap(),
            delta_invert_sd_index: cells.pop_front().unwrap(),
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
            prev_sd_index: cells.pop_front().unwrap(),
            prev_gc: cells.pop_front().unwrap(),
            prev_rw: cells.pop_front().unwrap(),
            prev_value: cells.pop_front().unwrap(),
            prev_value_ext: cells.pop_front().unwrap(),
            prev_is_empty: cells.pop_front().unwrap(),
        };

        let addr_ext_0_table = meta.lookup_table_column();
        let addr_ext_1_table = meta.lookup_table_column();

        let s_first_global_op = meta.complex_selector();
        Self::config_global_op(
            meta,
            s_first_global_op,
            &cells,
            true,
            gc_table,
            &addr_ext_0_table,
            &addr_ext_1_table,
        );

        let s_global_op = meta.complex_selector();
        Self::config_global_op(
            meta,
            s_global_op,
            &cells,
            false,
            gc_table,
            &addr_ext_0_table,
            &addr_ext_1_table,
        );

        GlobalOpChipConfig {
            advices,
            cells,
            s_first_global_op,
            s_global_op,
            addr_ext_0_table,
            addr_ext_1_table,
        }
    }

    fn config_global_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &GlobalOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
        addr_ext0_table: &TableColumn,
        addr_ext1_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        let mut addr_ext0_lookup = Vec::new();
        let mut addr_ext1_lookup = Vec::new();
        Self::constrain_global_op(
            cells,
            &mut constraints,
            is_first_op,
            &mut gc_lookups,
            &mut addr_ext0_lookup,
            &mut addr_ext1_lookup,
        );

        meta.create_gate("constrain global op", |meta| {
            let selector = meta.query_selector(selector);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, selector.clone() * constraint))
        });

        for lookup in gc_lookups {
            meta.lookup("global gc", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *gc_table)]
            });
        }
        for lookup in addr_ext0_lookup {
            meta.lookup("global address ext_0", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext0_table)]
            });
        }
        for lookup in addr_ext1_lookup {
            meta.lookup("global address ext_1", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext1_table)]
            });
        }
        // todo: lookup address_ext_0, address_ext_1 for range check
    }

    fn constrain_global_op(
        cells: &GlobalOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
        addr_ext0_lookups: &mut Vec<Expression<F>>,
        addr_ext1_lookups: &mut Vec<Expression<F>>,
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
                "counter == prev_counter+1",
                cond.clone()
                    * (cells.counter.expression.clone()
                        - cells.prev_counter.expression.clone()
                        - 1.expr()),
            ));
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "for read op: value == prev_value",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read.clone(),
            ));
            constraints.push((
                "for read op: value_ext == prev_value_ext",
                cond.clone()
                    * (cells.value_ext.expression.clone()
                        - cells.prev_value_ext.expression.clone())
                    * is_read,
            ));

            // if address/sd_index != prev_address/prev_sd_index and rw == Read
            // todo: check merkle proof

            // rw == 0 || rw == 1
            constraints.push((
                "rw = 0|1",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1.expr()),
            ));

            // for ops with same address/sd_index/addr_ext0/addr_ext1, gc must be great than prev_gc
            // 1.constrain delta_invert: (a - b) * inverse(a - b) must be 1 or 0
            // 2.lookup gc_table when address/sd_index/addr_ext0/addr_ext1 is same with previous

            let delt_address =
                cells.address.expression.clone() - cells.prev_address.expression.clone();
            constraints.push((
                "delt_invert_address: (a - b) * inverse(a - b) = 0|1",
                cond.clone()
                    * delt_address.clone()
                    * (delt_address.clone() * cells.delta_invert_address.expression.clone()
                        - 1.expr()),
            ));
            let delt_sd_index =
                cells.sd_index.expression.clone() - cells.prev_sd_index.expression.clone();
            constraints.push((
                "delt_invert_sd_index: (a - b) * inverse(a - b) = 0|1",
                cond.clone()
                    * delt_sd_index.clone()
                    * (delt_sd_index.clone() * cells.delta_invert_sd_index.expression.clone()
                        - 1.expr()),
            ));
            let delt_addr_ext_0 = cells.address_ext_0.expression.clone()
                - cells.prev_address_ext_0.expression.clone();
            constraints.push((
                "delt_invert_address_ext_0: (a - b) * inverse(a - b) = 0|1",
                cond.clone()
                    * delt_addr_ext_0.clone()
                    * (delt_addr_ext_0.clone() * cells.delta_invert_addr_ext_0.expression.clone()
                        - 1.expr()),
            ));
            let delt_addr_ext_1 = cells.address_ext_1.expression.clone()
                - cells.prev_address_ext_1.expression.clone();
            constraints.push((
                "delt_invert_address_ext_1: (a - b) * inverse(a - b) = 0|1",
                cond.clone()
                    * delt_addr_ext_1.clone()
                    * (delt_addr_ext_1.clone() * cells.delta_invert_addr_ext_1.expression.clone()
                        - 1.expr()),
            ));
            gc_lookups.push(
                cond.clone()
                    * (1.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * (1.expr()
                        - delt_sd_index.clone() * cells.delta_invert_sd_index.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_0.clone()
                            * cells.delta_invert_addr_ext_0.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_1.clone()
                            * cells.delta_invert_addr_ext_1.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // TODO: address part validation check
            // todo: address must belong to the address list?
            // todo: sd_index must belong to the sd_index list?
            // address_ext_* range check
            for i in 0..MAX_ADDRESS_EXT_LENGTH {
                addr_ext0_lookups.push(cond.clone() * cells.addr_ext_bytes[i].expression.clone());
            }
            addr_ext1_lookups.push(cond.clone() * cells.address_ext_1.expression.clone());

            // addr_ext_bytes validation
            let bytes = FieldBytes16bit::from(cells.addr_ext_bytes.clone()).expr();
            let constraint = cond.clone() * (cells.address_ext_0.expression.clone() - bytes);
            constraints.push(("addr_ext_bytes check", constraint));

            // TODO: address monotonic check.  should we make a common `gte` gadget instead of those lookup?
            // -[ ] address must be great than or equal to prev_address?
            // -[ ] for same address, sd_index must be great than or equal to prev_sd_index
            // -[x] for same address/sd_index, must have `addr_ext_0 >= prev_addr_ext_0`
            // -[x] for same address/sd_index/addr_ext0, must have `addr_ext_1 >= prev_addr_ext_1`

            // if same address/sd_index, addr_ext_0 must be great than or equal to prev_addr_ext_0
            // for i in 0..MAX_ADDRESS_EXT_LENGTH {
            //     addr_ext0_lookups.push(
            //         cond.clone()
            //             * (1.expr()
            //                 - delt_address.clone() * cells.delta_invert_address.expression.clone())
            //             * (1.expr()
            //                 - delt_sd_index.clone()
            //                     * cells.delta_invert_sd_index.expression.clone())
            //             * (cells.addr_ext_bytes[i].expression.clone()
            //                 - cells.prev_addr_ext_bytes[i].expression.clone()),
            //     );
            // }
            for i in (0..MAX_ADDRESS_EXT_LENGTH).rev() {
                let delta = cells.addr_ext_bytes[i].expression.clone()
                    - cells.prev_addr_ext_bytes[i].expression.clone();
                let init = cond.clone()
                    * (1.expr()
                        - delt_address.clone() * cells.delta_invert_address.expression.clone())
                    * (1.expr()
                        - delt_sd_index.clone() * cells.delta_invert_sd_index.expression.clone())
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

                addr_ext0_lookups.push(val);
            }

            // if same address/sd_index/addr_ext_0, addr_ext_1 must be great than or equal to prev_addr_ext_1
            addr_ext1_lookups.push(
                cond * (1.expr() - delt_address * cells.delta_invert_address.expression.clone())
                    * (1.expr() - delt_sd_index * cells.delta_invert_sd_index.expression.clone())
                    * (1.expr()
                        - delt_addr_ext_0 * cells.delta_invert_addr_ext_0.expression.clone())
                    * delt_addr_ext_1,
            );

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
        }

        let (prev_address, prev_sd_index, prev_addr_ext_0, prev_addr_ext_1) = match prev_op {
            None => (F::zero(), F::zero(), F::zero(), F::zero()),
            Some(v) => (
                v.address.0,
                v.sd_index.0,
                v.address_ext_0.0,
                v.address_ext_1.0,
            ),
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
            op.address_ext_1.0.delta_invert(prev_addr_ext_1),
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
        circuit_config: &CircuitConfig,
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

        // TODO: we should only need one addr_ext table. refactor this.
        assign_index_table(
            layouter,
            "addr_ext0_table",
            self.config.addr_ext_0_table,
            circuit_config.word_size,
        )
        .ok()?;
        assign_index_table(
            layouter,
            "addr_ext1_table",
            self.config.addr_ext_1_table,
            circuit_config.word_size,
        )
        .ok()?;
        last_global_counter
    }
}
