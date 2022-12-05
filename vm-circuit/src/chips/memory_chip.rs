// Copyright (c) zkMove Authors

use crate::chips::memory_chip::global_op_chip::{GlobalOpChip, GlobalOpChipConfig};
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::{CircuitConfig, Witness};
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

pub const MEM_CHIP_WIDTH: usize = 9; //max(STACK_OP_CHIP_WIDTH, LOCALS_OP_CHIP_WIDTH, GLOBAL_OP_CHIP_WIDTH)

#[derive(Clone, Debug)]
pub struct MemoryChipConfig<F: FieldExt> {
    advices: [Column<Advice>; MEM_CHIP_WIDTH],
    stack_op_config: StackOpChipConfig<F>,
    locals_op_config: LocalsOpChipConfig<F>,
    global_op_config: GlobalOpChipConfig<F>,
    s_add_counters: Selector,
    gc_table: TableColumn,
    call_index_table: TableColumn,
    locals_index_table: TableColumn,
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
        let call_index_table = meta.lookup_table_column();
        let locals_index_table = meta.lookup_table_column();
        let stack_op_config = StackOpChip::configure(meta, advices, &gc_table);
        let locals_op_config = LocalsOpChip::configure(
            meta,
            advices,
            &gc_table,
            &call_index_table,
            &locals_index_table,
        );
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
            call_index_table,
            locals_index_table,
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
        let stack_ops_num = self.witness.circuit_config.stack_ops_num.unwrap_or(0);
        let locals_ops_num = self.witness.circuit_config.locals_ops_num.unwrap_or(0);
        let global_ops_num = self.witness.circuit_config.global_ops_num.unwrap_or(0);

        let stack_op_chip = StackOpChip::<F>::construct(self.config.stack_op_config.clone(), ());
        let mut last_stack_counter: Option<AssignedCell<F, F>> = None;

        if !stack_ops.is_empty() || stack_ops_num > 0 {
            layouter.assign_region(
                || "stack operations",
                |mut region: Region<'_, F>| {
                    let mut counter = 0;
                    for (index, op) in stack_ops.iter().enumerate() {
                        counter = index + 1;
                        let assigned_counter = if index == 0 {
                            stack_op_chip
                                .config
                                .s_first_stack_op
                                .enable(&mut region, index)?;
                            stack_op_chip.assign(&mut region, index, op, counter, false)?
                        } else {
                            stack_op_chip.config.s_stack_op.enable(&mut region, index)?;
                            stack_op_chip.assign(&mut region, index, op, counter, false)?
                        };
                        if counter == stack_ops.len() {
                            last_stack_counter = Some(assigned_counter);
                        }
                    }

                    // If the number of stack ops is less than stack_ops_num set by user, fill with
                    // empty op. This happened when the execution path is not fixed, for example,
                    // if there is loop in the code.
                    if stack_ops.len() < stack_ops_num {
                        for index in stack_ops.len()..stack_ops_num {
                            let assigned_counter = if index == 0 {
                                stack_op_chip
                                    .config
                                    .s_first_stack_op
                                    .enable(&mut region, index)?;
                                stack_op_chip.assign(
                                    &mut region,
                                    index,
                                    &ConvertedRWOperation::empty(),
                                    counter,
                                    true,
                                )?
                            } else {
                                stack_op_chip.config.s_stack_op.enable(&mut region, index)?;
                                stack_op_chip.assign(
                                    &mut region,
                                    index,
                                    &ConvertedRWOperation::empty(),
                                    counter,
                                    true,
                                )?
                            };
                            last_stack_counter = Some(assigned_counter);
                        }
                    }
                    Ok(())
                },
            )?;
        }

        let locals_op_chip = LocalsOpChip::<F>::construct(self.config.locals_op_config.clone(), ());
        let mut last_locals_counter: Option<AssignedCell<F, F>> = None;

        if !locals_ops.is_empty() || locals_ops_num > 0 {
            layouter.assign_region(
                || "locals operations",
                |mut region: Region<'_, F>| {
                    let mut prev_op = None;
                    let mut counter = 0;
                    for (index, op) in locals_ops.iter().enumerate() {
                        counter = index + 1;
                        let assigned_counter = if index == 0 {
                            locals_op_chip
                                .config
                                .s_first_locals_op
                                .enable(&mut region, index)?;
                            locals_op_chip.assign(&mut region, index, op, counter, None, false)?
                        } else {
                            locals_op_chip
                                .config
                                .s_locals_op
                                .enable(&mut region, index)?;
                            locals_op_chip.assign(
                                &mut region,
                                index,
                                op,
                                counter,
                                prev_op,
                                false,
                            )?
                        };
                        if counter == locals_ops.len() {
                            last_locals_counter = Some(assigned_counter);
                        }
                        prev_op = Some(op.clone());
                    }

                    // If the number of locals ops is less than locals_ops_num set by user, fill with
                    // empty locals op.
                    if locals_ops.len() < locals_ops_num {
                        for index in locals_ops.len()..locals_ops_num {
                            let assigned_counter = if index == 0 {
                                locals_op_chip
                                    .config
                                    .s_first_locals_op
                                    .enable(&mut region, index)?;
                                locals_op_chip.assign(
                                    &mut region,
                                    index,
                                    &ConvertedRWOperation::empty(),
                                    counter,
                                    None,
                                    true,
                                )?
                            } else {
                                locals_op_chip
                                    .config
                                    .s_locals_op
                                    .enable(&mut region, index)?;
                                locals_op_chip.assign(
                                    &mut region,
                                    index,
                                    &ConvertedRWOperation::empty(),
                                    counter,
                                    prev_op,
                                    true,
                                )?
                            };

                            last_locals_counter = Some(assigned_counter);
                            prev_op = Some(ConvertedRWOperation::empty());
                        }
                    }

                    Ok(())
                },
            )?;
        }

        let global_op_chip = GlobalOpChip::<F>::construct(self.config.global_op_config.clone(), ());
        let mut last_global_counter: Option<AssignedCell<F, F>> = None;

        if !global_ops.is_empty() || global_ops_num > 0 {
            layouter.assign_region(
                || "global operations",
                |mut region: Region<'_, F>| {
                    let mut prev_op = None;
                    let mut counter = 0;
                    for (index, op) in global_ops.iter().enumerate() {
                        counter = index + 1;
                        let assigned_counter = if index == 0 {
                            global_op_chip
                                .config
                                .s_first_global_op
                                .enable(&mut region, index)?;
                            global_op_chip.assign(&mut region, index, op, counter, None, false)?
                        } else {
                            global_op_chip
                                .config
                                .s_global_op
                                .enable(&mut region, index)?;
                            global_op_chip.assign(
                                &mut region,
                                index,
                                op,
                                counter,
                                prev_op,
                                false,
                            )?
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
                                global_op_chip
                                    .config
                                    .s_first_global_op
                                    .enable(&mut region, index)?;
                                global_op_chip.assign(
                                    &mut region,
                                    index,
                                    &ConvertedRWOperation::empty(),
                                    counter,
                                    None,
                                    true,
                                )?
                            } else {
                                global_op_chip
                                    .config
                                    .s_global_op
                                    .enable(&mut region, index)?;
                                global_op_chip.assign(
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
            )?;
        }

        layouter.assign_region(
            || "add counter",
            |mut region: Region<'_, F>| {
                self.config.s_add_counters.enable(&mut region, 0)?;

                if let Some(assigned_last_stack_counter) = &last_stack_counter {
                    let counter_stack = region.assign_advice(
                        || "counter_stack",
                        self.config.advices[0],
                        0,
                        || {
                            let value_ref = assigned_last_stack_counter
                                .value()
                                .ok_or(Error::Synthesis)?;
                            Ok(*value_ref)
                        },
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
                        || Ok(F::zero()),
                    )?;
                }

                if let Some(assigned_last_locals_counter) = &last_locals_counter {
                    let counter_locals = region.assign_advice(
                        || "counter_locals",
                        self.config.advices[1],
                        0,
                        || {
                            let value_ref = assigned_last_locals_counter
                                .value()
                                .ok_or(Error::Synthesis)?;
                            Ok(*value_ref)
                        },
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
                        || Ok(F::zero()),
                    )?;
                }

                if let Some(assigned_last_global_counter) = &last_global_counter {
                    let counter_global = region.assign_advice(
                        || "counter_global",
                        self.config.advices[2],
                        0,
                        || {
                            let value_ref = assigned_last_global_counter
                                .value()
                                .ok_or(Error::Synthesis)?;
                            Ok(*value_ref)
                        },
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
                        || Ok(F::zero()),
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
                        || Ok(F::zero()),
                    )?;
                } else {
                    (0..=last_step_gc)
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("gc_table[{}]", i),
                                self.config.gc_table,
                                i,
                                || Ok(F::from_u128(i as u128)),
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
                                || Ok(F::from_u128(i as u128)),
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))?;
                }

                Ok(())
            },
        )?;

        layouter.assign_table(
            || "call_index_table",
            |mut table_column| {
                (0..=circuit_config.max_call_index)
                    .map(|i| {
                        table_column.assign_cell(
                            || format!("call_index_table[{}]", i),
                            self.config.call_index_table,
                            i,
                            || Ok(F::from_u128(i as u128)),
                        )
                    })
                    .fold(Ok(()), |acc, res| acc.and(res))
            },
        )?;

        layouter.assign_table(
            || "locals_index_table",
            |mut table_column| {
                (0..=circuit_config.max_locals_size)
                    .map(|i| {
                        table_column.assign_cell(
                            || format!("locals_index_table[{}]", i),
                            self.config.locals_index_table,
                            i,
                            || Ok(F::from_u128(i as u128)),
                        )
                    })
                    .fold(Ok(()), |acc, res| acc.and(res))
            },
        )?;

        Ok(())
    }
}
