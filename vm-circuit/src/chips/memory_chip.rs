// Copyright (c) zkMove Authors

use crate::chips::memory_chip::global_op_chip::{GlobalOpChip, GlobalOpChipConfig};
use crate::witness::rw_operations::{ConvertedRWOperation, RWOperation};
use crate::witness::{CircuitConfig, Witness};
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{Advice, Column};
use halo2_proofs::plonk::{Selector, TableColumn};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use locals_op_chip::{LocalsOpChip, LocalsOpChipConfig};
use logger::prelude::*;
use stack_op_chip::{StackOpChip, StackOpChipConfig};

pub mod global_op_chip;
pub mod locals_op_chip;
pub mod stack_op_chip;

// Memory chip is used to prove memory coherence - each load from memory(locals/stack/global)
// retrieves the last value stored there. The circuit input is the rw operations sorted by
// address(locals index/stack address). For each address, we constrain the value we read
// is equal to the value we just write.
//
// We don't need to constrain the 'sort by address' process, but need to constrain rw ops
// in the execution steps is equal to the sorted rw ops. To do this, we need to:
// 1. in execution chip, lookup rw ops of each execution step in the sorted rw operations,
// 2. in execution chip, constrain the strict monotonic increment of gc.
// 3. make sure total number of sorted rw operations is equal to the gc of the last
// execution step.

pub const MEM_CHIP_WIDTH: usize = 14; //max(STACK_OP_CHIP_WIDTH, LOCALS_OP_CHIP_WIDTH, GLOBAL_OP_CHIP_WIDTH)

#[derive(Clone, Debug)]
pub struct MemoryChipConfig<F: FieldExt> {
    advices: [Column<Advice>; MEM_CHIP_WIDTH],
    stack_op_config: StackOpChipConfig<F>,
    locals_op_config: LocalsOpChipConfig<F>,
    global_op_config: GlobalOpChipConfig<F>,
    s_add_counters: Selector,
    gc_table: TableColumn,
}

#[derive(Clone, Debug)]
pub struct MemoryChip<F: FieldExt> {
    pub witness: Witness<F>,
    pub config: MemoryChipConfig<F>,
}

impl<F: FieldExt> Chip<F> for MemoryChip<F> {
    type Config = MemoryChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> MemoryChip<F> {
    pub fn construct(
        witness: Witness<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self { witness, config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        let advices = [(); MEM_CHIP_WIDTH].map(|_| meta.advice_column());
        let gc_table = meta.lookup_table_column();
        let stack_op_config = StackOpChip::configure(meta, advices, &gc_table);
        let locals_op_config = LocalsOpChip::configure(meta, advices, &gc_table);
        let global_op_config = GlobalOpChip::configure(meta, advices, &gc_table);

        for column in &advices {
            meta.enable_equality(*column);
        }

        let s_add_counters = meta.selector();
        meta.create_gate("add counters", |meta| {
            let s_add_counters = meta.query_selector(s_add_counters);
            let last_stack_counter = meta.query_advice(advices[0], Rotation::cur());
            let last_locals_counter = meta.query_advice(advices[1], Rotation::cur());
            let last_global_counter = meta.query_advice(advices[2], Rotation::cur());
            let last_step_gc = meta.query_advice(advices[3], Rotation::cur());
            vec![
                s_add_counters
                    * (last_stack_counter + last_locals_counter + last_global_counter
                        - last_step_gc),
            ]
        });

        MemoryChipConfig {
            advices,
            stack_op_config,
            locals_op_config,
            global_op_config,
            s_add_counters,
            gc_table,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        circuit_config: &CircuitConfig,
        last_step_gc_cell: AssignedCell<F, F>,
        stack_ops: Vec<ConvertedRWOperation<F>>,
        locals_ops: Vec<ConvertedRWOperation<F>>,
        global_ops: Vec<ConvertedRWOperation<F>>,
    ) -> Result<(), Error> {
        let (mut real_stack_ops_len, mut real_locals_ops_len, mut real_global_ops_len) =
            (0usize, 0usize, 0usize);
        self.witness.rw_operations.0.iter().for_each(|op| match op {
            RWOperation::LocalsOp(_) => real_locals_ops_len += 1,
            RWOperation::StackOp(_) => real_stack_ops_len += 1,
            RWOperation::GlobalOp(_) => real_global_ops_len += 1,
        });

        let stack_ops_num = self.witness.circuit_config.stack_ops_num.unwrap_or(0);
        let locals_ops_num = self.witness.circuit_config.locals_ops_num.unwrap_or(0);
        let global_ops_num = self.witness.circuit_config.global_ops_num.unwrap_or(0);

        let stack_op_chip = StackOpChip::<F>::construct(self.config.stack_op_config.clone(), ());
        let last_stack_counter =
            stack_op_chip.assign(layouter, circuit_config, stack_ops, real_stack_ops_len);

        let locals_op_chip = LocalsOpChip::<F>::construct(self.config.locals_op_config.clone(), ());
        let last_locals_counter =
            locals_op_chip.assign(layouter, circuit_config, locals_ops, real_locals_ops_len);

        let global_op_chip = GlobalOpChip::<F>::construct(self.config.global_op_config.clone(), ());
        let last_global_counter =
            global_op_chip.assign(layouter, circuit_config, global_ops, real_global_ops_len);

        layouter.assign_region(
            || "add counter",
            |mut region: Region<'_, F>| {
                self.config.s_add_counters.enable(&mut region, 0)?;

                if let Some(assigned_last_stack_counter) = &last_stack_counter {
                    let counter_stack = region.assign_advice(
                        || "counter_stack",
                        self.config.advices[0],
                        0,
                        || assigned_last_stack_counter.value().copied(),
                    )?;
                    region.constrain_equal(
                        assigned_last_stack_counter.cell(),
                        counter_stack.cell(),
                    )?;
                } else {
                    region.assign_advice(
                        || "counter_stack",
                        self.config.advices[0],
                        0,
                        || CircuitValue::known(F::zero()),
                    )?;
                }

                if let Some(assigned_last_locals_counter) = &last_locals_counter {
                    let counter_locals = region.assign_advice(
                        || "counter_locals",
                        self.config.advices[1],
                        0,
                        || assigned_last_locals_counter.value().copied(),
                    )?;
                    region.constrain_equal(
                        assigned_last_locals_counter.cell(),
                        counter_locals.cell(),
                    )?;
                } else {
                    region.assign_advice(
                        || "counter_locals",
                        self.config.advices[1],
                        0,
                        || CircuitValue::known(F::zero()),
                    )?;
                }

                if let Some(assigned_last_global_counter) = &last_global_counter {
                    let counter_global = region.assign_advice(
                        || "counter_global",
                        self.config.advices[2],
                        0,
                        || assigned_last_global_counter.value().copied(),
                    )?;
                    region.constrain_equal(
                        assigned_last_global_counter.cell(),
                        counter_global.cell(),
                    )?;
                } else {
                    region.assign_advice(
                        || "counter_global",
                        self.config.advices[2],
                        0,
                        || CircuitValue::known(F::zero()),
                    )?;
                }

                last_step_gc_cell.copy_advice(
                    || "last step gc",
                    &mut region,
                    self.config.advices[3],
                    0,
                )?;

                Ok(())
            },
        )?;

        let last_step_gc = self
            .witness
            .exec_steps
            .last()
            .ok_or_else(|| {
                error!("last step gc is None");
                Error::Synthesis
            })?
            .gc;

        layouter.assign_table(
            || "gc_table",
            |mut table_column| {
                if last_step_gc == 0 {
                    table_column.assign_cell(
                        || "gc_table[0]".to_string(),
                        self.config.gc_table,
                        0,
                        || CircuitValue::known(F::zero()),
                    )?;
                } else {
                    (0..=last_step_gc)
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("gc_table[{}]", i),
                                self.config.gc_table,
                                i,
                                || CircuitValue::known(F::from_u128(i as u128)),
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))?;
                }

                let ops_num = stack_ops_num + locals_ops_num + global_ops_num;

                if last_step_gc < ops_num {
                    ((last_step_gc + 1)..=ops_num)
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("gc_table[{}]", i),
                                self.config.gc_table,
                                i,
                                || CircuitValue::known(F::from_u128(i as u128)),
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
