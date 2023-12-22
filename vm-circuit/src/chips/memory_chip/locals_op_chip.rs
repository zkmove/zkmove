// Copyright (c) zkMove Authors

use crate::chips::memory_chip::MEM_CHIP_WIDTH;
use crate::chips::utilities::*;
use crate::witness::rw_operations::{ConvertedRWOperation, RW};
use crate::witness::CircuitConfig;
use halo2_base::halo2_proofs::circuit::Value as CircuitValue;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region};
use halo2_base::halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn,
};
use logger::prelude::*;
use std::collections::VecDeque;
use std::marker::PhantomData;
use types::Field;

pub const LOCALS_OP_CHIP_WIDTH: usize = 11;

#[derive(Clone, Debug)]
pub struct LocalsOpCells<F: Field> {
    pub counter: Cell<F>, // the total number of locals operations
    pub frame_index: Cell<F>,
    pub index: Cell<F>,
    pub addr_ext: Cell<F>,
    pub gc: Cell<F>,
    pub rw: Cell<F>,
    pub value: Cell<F>,
    pub is_empty: Cell<F>, // is empty op or not
    // delta_invert_xxx is used to constrain the strict monotonic
    // increment of gc for the same locals
    pub delta_invert_frame_index: Cell<F>,
    pub delta_invert_idx: Cell<F>,
    pub delta_invert_addr_ext: Cell<F>,

    pub prev_counter: Cell<F>,
    pub prev_frame_index: Cell<F>,
    pub prev_index: Cell<F>,
    pub prev_addr_ext: Cell<F>,
    pub prev_gc: Cell<F>,
    pub prev_rw: Cell<F>,
    pub prev_value: Cell<F>,
    pub prev_is_empty: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct LocalsOpChipConfig<F: Field> {
    pub advices: [Column<Advice>; MEM_CHIP_WIDTH],
    pub cells: LocalsOpCells<F>,
    pub s_first_locals_op: Selector,
    pub s_locals_op: Selector,
    frame_index_table: TableColumn,
    locals_index_table: TableColumn,
    addr_ext_table: TableColumn,
}

pub struct LocalsOpChip<F: Field> {
    pub config: LocalsOpChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for LocalsOpChip<F> {
    type Config = LocalsOpChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> LocalsOpChip<F> {
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
        let frame_index_table = meta.lookup_table_column();
        let locals_index_table = meta.lookup_table_column();
        let addr_ext_table = meta.lookup_table_column();

        let mut cells = VecDeque::with_capacity(LOCALS_OP_CHIP_WIDTH * 2);
        meta.create_gate("locals op chip", |meta| {
            for i in 0..LOCALS_OP_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            // previous op, without delta_invert cells
            for i in 0..(LOCALS_OP_CHIP_WIDTH - 3) {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::ZERO)]
        });

        let cells = LocalsOpCells {
            counter: cells.pop_front().unwrap(),
            frame_index: cells.pop_front().unwrap(),
            index: cells.pop_front().unwrap(),
            addr_ext: cells.pop_front().unwrap(),
            gc: cells.pop_front().unwrap(),
            rw: cells.pop_front().unwrap(),
            value: cells.pop_front().unwrap(),
            is_empty: cells.pop_front().unwrap(),
            delta_invert_frame_index: cells.pop_front().unwrap(),
            delta_invert_idx: cells.pop_front().unwrap(),
            delta_invert_addr_ext: cells.pop_front().unwrap(),

            prev_counter: cells.pop_front().unwrap(),
            prev_frame_index: cells.pop_front().unwrap(),
            prev_index: cells.pop_front().unwrap(),
            prev_addr_ext: cells.pop_front().unwrap(),
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
            &frame_index_table,
            &locals_index_table,
            &addr_ext_table,
        );

        let s_locals_op = meta.complex_selector();
        Self::config_locals_op(
            meta,
            s_locals_op,
            &cells,
            false,
            gc_table,
            &frame_index_table,
            &locals_index_table,
            &addr_ext_table,
        );

        LocalsOpChipConfig {
            advices,
            cells,
            s_first_locals_op,
            s_locals_op,
            frame_index_table,
            locals_index_table,
            addr_ext_table,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn config_locals_op(
        meta: &mut ConstraintSystem<F>,
        selector: Selector,
        cells: &LocalsOpCells<F>,
        is_first_op: bool,
        gc_table: &TableColumn,
        frame_index_table: &TableColumn,
        locals_index_table: &TableColumn,
        addr_ext_table: &TableColumn,
    ) {
        let mut constraints = Vec::new();
        let mut gc_lookups = Vec::new();
        let mut frame_index_lookups = Vec::new();
        let mut locals_index_lookups = Vec::new();
        let mut addr_ext_lookups = Vec::new();
        Self::constrain_locals_op(
            cells,
            &mut constraints,
            is_first_op,
            &mut gc_lookups,
            &mut frame_index_lookups,
            &mut locals_index_lookups,
            &mut addr_ext_lookups,
        );

        meta.create_gate("constrain locals op", |meta| {
            let selector = meta.query_selector(selector);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, selector.clone() * constraint))
        });

        for lookup in gc_lookups {
            meta.lookup("locals gc", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *gc_table)]
            });
        }

        for lookup in frame_index_lookups {
            meta.lookup("locals frame index", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *frame_index_table)]
            });
        }

        for lookup in locals_index_lookups {
            meta.lookup("locals index", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *locals_index_table)]
            });
        }

        for lookup in addr_ext_lookups {
            meta.lookup("locals address ext_0", |meta| {
                let selector = meta.query_selector(selector);
                vec![(selector * lookup, *addr_ext_table)]
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn constrain_locals_op(
        cells: &LocalsOpCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        is_first: bool,
        gc_lookups: &mut Vec<Expression<F>>,
        frame_index_lookups: &mut Vec<Expression<F>>,
        locals_index_lookups: &mut Vec<Expression<F>>,
        //addr_ext_lookups: &mut <Expression<F>>,
        _addr_ext_lookups: &mut [Expression<F>],
    ) {
        constraints.push((
            "is_empty is bool",
            (cells.is_empty.expression.clone() - 1u64.expr()) * cells.is_empty.expression.clone(),
        ));
        let cond = 1u64.expr() - cells.is_empty.expression.clone();

        if is_first {
            // for the first op: counter == 1, rw == Write
            // note, ether frame_index or index may NOT be 0
            constraints.push((
                "first locals op",
                cond.clone() * (cells.counter.expression.clone() - 1u64.expr()),
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
                        - 1u64.expr()),
            ));

            // rw == 0 || rw == 1
            constraints.push((
                "rw",
                cond.clone()
                    * cells.rw.expression.clone()
                    * (cells.rw.expression.clone() - 1u64.expr()),
            ));
            // for read op: value == prev_value
            let is_read = (RW::WRITE as u64).expr() - cells.rw.expression.clone();
            constraints.push((
                "read op",
                cond.clone()
                    * (cells.value.expression.clone() - cells.prev_value.expression.clone())
                    * is_read,
            ));

            // constrain delta_invert: (a - b) * inverse(a - b) must be 1 or 0
            let delt_frame_index =
                cells.frame_index.expression.clone() - cells.prev_frame_index.expression.clone();
            constraints.push((
                "delt_invert_frame_index",
                cond.clone()
                    * delt_frame_index.clone()
                    * (delt_frame_index.clone()
                        * cells.delta_invert_frame_index.expression.clone()
                        - 1u64.expr()),
            ));
            let delt_index = cells.index.expression.clone() - cells.prev_index.expression.clone();
            constraints.push((
                "delt_invert_index",
                cond.clone()
                    * delt_index.clone()
                    * (delt_index.clone() * cells.delta_invert_idx.expression.clone()
                        - 1u64.expr()),
            ));
            let delt_addr_ext =
                cells.addr_ext.expression.clone() - cells.prev_addr_ext.expression.clone();
            constraints.push((
                "delt_invert_address_ext",
                cond.clone()
                    * delt_addr_ext.clone()
                    * (delt_addr_ext.clone() * cells.delta_invert_addr_ext.expression.clone()
                        - 1u64.expr()),
            ));

            // address change, then rw must be Write
            // case A: if frame_index != prev_frame_index
            //         then rw == Write
            constraints.push((
                "frame_index_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * delt_frame_index.clone(),
            ));
            // case B: if frame_index == prev_frame_index  and
            //            index != prev_index
            //         then rw == Write
            constraints.push((
                "index_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * (1u64.expr()
                        - delt_frame_index.clone()
                            * cells.delta_invert_frame_index.expression.clone())
                    * delt_index.clone(),
            ));
            // case C: if frame_index == prev_frame_index  and
            //            index == prev_index and
            //            addr_ext != prev_addr_ext
            //         then rw == Write
            constraints.push((
                "addr_ext_change",
                cond.clone()
                    * (cells.rw.expression.clone() - (RW::WRITE as u64).expr())
                    * (1u64.expr()
                        - delt_frame_index.clone()
                            * cells.delta_invert_frame_index.expression.clone())
                    * (1u64.expr()
                        - delt_index.clone() * cells.delta_invert_idx.expression.clone())
                    * delt_addr_ext.clone(),
            ));

            // for ops with same address, gc must be great than prev_gc
            // lookup gc_table when frame_index/index is same with previous
            gc_lookups.push(
                cond.clone()
                    * (1u64.expr()
                        - delt_frame_index.clone()
                            * cells.delta_invert_frame_index.expression.clone())
                    * (1u64.expr()
                        - delt_index.clone() * cells.delta_invert_idx.expression.clone())
                    * (1u64.expr()
                        - delt_addr_ext * cells.delta_invert_addr_ext.expression.clone())
                    * (cells.gc.expression.clone() - cells.prev_gc.expression.clone()),
            );

            // address validation check
            // frame_index must be less than max_frame_index
            frame_index_lookups.push(cond.clone() * cells.frame_index.expression.clone());
            // index must be less than max_locals_size
            locals_index_lookups.push(cond.clone() * cells.index.expression.clone());
            // address_ext must be less than max_locals_size
            // TODO. address extend validation
            // addr_ext_lookups.push(cond.clone() * cells.addr_ext.expression.clone());

            // address monotonic increment
            // Case A: frame_index must be great than or equal to prev_frame_index
            frame_index_lookups.push(cond.clone() * delt_frame_index.clone());
            // Case B: if same frame_index, index must be great than or equal to prev_index
            locals_index_lookups.push(
                cond * (1u64.expr()
                    - delt_frame_index * cells.delta_invert_frame_index.expression.clone())
                    * delt_index,
            );
            // Case C: if same frame_index/index,
            //         addr_ext must be great than or equal to prev_addr_ext
            // TODO. address extend validation
            // addr_ext_lookups.push(
            //     cond.clone()
            //         * (1u64.expr()
            //             - delt_frame_index.clone()
            //                 * cells.delta_invert_frame_index.expression.clone())
            //         * (1u64.expr() - delt_index.clone() * cells.delta_invert_idx.expression.clone())
            //         * delt_addr_ext.clone(),
            // );

            // empty op
            constraints.push((
                "empty op counter",
                cells.is_empty.expression.clone()
                    * (cells.counter.expression.clone() - cells.prev_counter.expression.clone()),
            ));
        }
    }

    // assign each cell of the locals operation, return assigned cell for counter
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

            self.config.cells.frame_index.assign_equality(
                region,
                offset,
                op.frame_index.1.clone().ok_or_else(|| {
                    error!("frame_index assigned cell is None");
                    Error::Synthesis
                })?,
                "frame_index",
            )?;

            self.config.cells.index.assign_equality(
                region,
                offset,
                op.address.1.clone().ok_or_else(|| {
                    error!("index assigned cell is None");
                    Error::Synthesis
                })?,
                "index",
            )?;

            self.config.cells.addr_ext.assign_equality(
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
        }

        let (prev_frame_index, prev_index, prev_addr_ext) = match prev_op {
            None => (F::ZERO, F::ZERO, F::ZERO),
            Some(v) => (v.frame_index.0, v.address.0, v.address_ext.0),
        };
        self.config.cells.delta_invert_frame_index.assign(
            region,
            offset,
            op.frame_index.0.delta_invert(prev_frame_index),
        )?;
        self.config.cells.delta_invert_idx.assign(
            region,
            offset,
            op.address.0.delta_invert(prev_index),
        )?;
        self.config.cells.delta_invert_addr_ext.assign(
            region,
            offset,
            op.address_ext.0.delta_invert(prev_addr_ext),
        )?;

        let is_empty = if is_empty { F::ONE } else { F::ZERO };
        self.config
            .cells
            .is_empty
            .assign(region, offset, Some(is_empty))?;

        Ok(assigned)
    }

    #[allow(clippy::manual_try_fold)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        circuit_config: &CircuitConfig,
        locals_ops: Vec<ConvertedRWOperation<F>>,
        real_locals_ops_len: usize,
    ) -> Option<AssignedCell<F, F>> {
        let mut last_locals_counter: Option<AssignedCell<F, F>> = None;

        if !locals_ops.is_empty() {
            layouter
                .assign_region(
                    || "locals operations",
                    |mut region: Region<'_, F>| {
                        let mut prev_op = None;
                        let mut counter = 0;
                        for (index, op) in locals_ops.iter().enumerate().take(real_locals_ops_len) {
                            counter = index + 1;
                            let assigned_counter = if index == 0 {
                                self.config.s_first_locals_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, false)?
                            } else {
                                self.config.s_locals_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, false)?
                            };
                            if counter == locals_ops.len() {
                                last_locals_counter = Some(assigned_counter);
                            }
                            prev_op = Some(op.clone());
                        }

                        // If the number of locals ops is less than locals_ops_num set by user, fill with
                        // empty locals op.

                        for (index, op) in locals_ops.iter().enumerate().skip(real_locals_ops_len) {
                            let assigned_counter = if index == 0 {
                                self.config.s_first_locals_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, None, true)?
                            } else {
                                self.config.s_locals_op.enable(&mut region, index)?;
                                self.assign_cell(&mut region, index, op, counter, prev_op, true)?
                            };

                            last_locals_counter = Some(assigned_counter);
                            prev_op = Some(op.clone());
                        }

                        Ok(())
                    },
                )
                .ok()?;
        }

        self.assign_table(layouter, circuit_config).ok()?;

        last_locals_counter
    }

    // a special table with solo column and the value same as index.
    // which is to garantuee value is among [0, max].
    #[allow(clippy::manual_try_fold)]
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
                            || format!("frame_index_table[{}]", i),
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
            "frame_index_table",
            self.config.frame_index_table,
            circuit_config.max_frame_index,
        )?;
        self.assign_index_table(
            layouter,
            "locals_index_table",
            self.config.locals_index_table,
            circuit_config.max_locals_size,
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
        let frame_index_table = circuit_config.max_frame_index + 1;
        let locals_index_table = circuit_config.max_locals_size + 1;
        let addr_ext_table = circuit_config.word_size + 1;

        frame_index_table
            .max(locals_index_table)
            .max(addr_ext_table)
    }
}
