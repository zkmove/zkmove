// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::locals_op_chip::{
    LocalsOpChip, LocalsOpChipConfig, MAX_CALL_INDEX, MAX_LOCALS_SIZE,
};
use crate::vm_circuit::chips::stack_op_chip::{StackOpChip, StackOpChipConfig};
use crate::vm_circuit::circuit_inputs::CircuitInputs;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column};
use halo2_proofs::plonk::{Selector, TableColumn};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use logger::prelude::*;

// Memory chip is used to prove memory coherence - each load from memory(locals/stack)
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

pub const MEM_CHIP_WIDTH: usize = 8; //max(STACK_OP_CHIP_WIDTH, LOCALS_OP_CHIP_WIDTH)

#[derive(Clone, Debug)]
pub struct MemoryChipConfig<F: FieldExt> {
    advices: [Column<Advice>; MEM_CHIP_WIDTH],
    stack_op_config: StackOpChipConfig<F>,
    locals_op_config: LocalsOpChipConfig<F>,
    s_add_counters: Selector,
    gc_table: TableColumn,
    call_index_table: TableColumn,
    locals_index_table: TableColumn,
}

#[derive(Clone, Debug)]
pub struct MemoryChip<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
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
        circuit_inputs: CircuitInputs<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            circuit_inputs,
            config,
        }
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

        // todo: evaluate the cost to enable equality
        for column in &advices {
            meta.enable_equality(*column);
        }

        let s_add_counters = meta.selector();
        meta.create_gate("add counters", |meta| {
            let s_add_counters = meta.query_selector(s_add_counters);
            let last_stack_counter = meta.query_advice(advices[0], Rotation::cur());
            let last_locals_counter = meta.query_advice(advices[1], Rotation::cur());
            let last_step_gc = meta.query_advice(advices[2], Rotation::cur());
            vec![s_add_counters * (last_stack_counter + last_locals_counter - last_step_gc)]
        });

        MemoryChipConfig {
            advices,
            stack_op_config,
            locals_op_config,
            s_add_counters,
            gc_table,
            call_index_table,
            locals_index_table,
        }
    }

    pub fn assign(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let stack_op_chip = StackOpChip::<F>::construct(self.config.stack_op_config.clone(), ());
        let stack_ops = &self.circuit_inputs.sorted_stack_ops.0;
        let mut last_stack_counter = None;

        layouter.assign_region(
            || "stack operations",
            |mut region: Region<'_, F>| {
                for (index, op) in stack_ops.iter().enumerate() {
                    let counter = index + 1;
                    let assigned_counter = if index == 0 {
                        stack_op_chip
                            .config
                            .s_first_stack_op
                            .enable(&mut region, index)?;
                        stack_op_chip.assign(&mut region, index, op, counter)?
                    } else {
                        stack_op_chip.config.s_stack_op.enable(&mut region, index)?;
                        stack_op_chip.assign(&mut region, index, op, counter)?
                    };
                    if counter == stack_ops.len() {
                        last_stack_counter = Some(assigned_counter);
                    }
                }
                Ok(())
            },
        )?;

        let locals_op_chip = LocalsOpChip::<F>::construct(self.config.locals_op_config.clone(), ());
        let mut last_locals_counter = None;

        layouter.assign_region(
            || "locals operations",
            |mut region: Region<'_, F>| {
                let locals_ops = &self.circuit_inputs.sorted_locals_ops.0;
                let mut prev_op = None;
                for (index, op) in locals_ops.iter().enumerate() {
                    let counter = index + 1;
                    let assigned_counter = if index == 0 {
                        locals_op_chip
                            .config
                            .s_first_locals_op
                            .enable(&mut region, index)?;
                        locals_op_chip.assign(&mut region, index, op, counter, None)?
                    } else {
                        locals_op_chip
                            .config
                            .s_locals_op
                            .enable(&mut region, index)?;
                        locals_op_chip.assign(&mut region, index, op, counter, prev_op)?
                    };
                    if counter == locals_ops.len() {
                        last_locals_counter = Some(assigned_counter);
                    }
                    prev_op = Some(op.clone());
                }
                Ok(())
            },
        )?;

        let last_step_gc = self
            .circuit_inputs
            .exec_steps
            .last()
            .ok_or_else(|| {
                error!("last step gc is None");
                Error::Synthesis
            })?
            .gc;

        layouter.assign_region(
            || "add counter",
            |mut region: Region<'_, F>| {
                self.config.s_add_counters.enable(&mut region, 0)?;

                if let Some(assigned_last_stack_counter) = &last_stack_counter {
                    let lhs = region.assign_advice(
                        || "lhs",
                        self.config.advices[0],
                        0,
                        || {
                            let value_ref = assigned_last_stack_counter
                                .value()
                                .ok_or(Error::Synthesis)?;
                            Ok(*value_ref)
                        },
                    )?;
                    region.constrain_equal(assigned_last_stack_counter.cell(), lhs.cell())?;
                } else {
                    region.assign_advice(|| "lhs", self.config.advices[0], 0, || Ok(F::zero()))?;
                }

                if let Some(assigned_last_locals_counter) = &last_locals_counter {
                    let rhs = region.assign_advice(
                        || "rhs",
                        self.config.advices[1],
                        0,
                        || {
                            let value_ref = assigned_last_locals_counter
                                .value()
                                .ok_or(Error::Synthesis)?;
                            Ok(*value_ref)
                        },
                    )?;
                    region.constrain_equal(assigned_last_locals_counter.cell(), rhs.cell())?;
                } else {
                    region.assign_advice(|| "rhs", self.config.advices[1], 0, || Ok(F::zero()))?;
                }

                region.assign_advice(
                    || "last step gc",
                    self.config.advices[2],
                    0,
                    || Ok(F::from_u128(last_step_gc as u128)),
                )?;
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "gc_table",
            |mut table_column| {
                if last_step_gc == 0 {
                    table_column.assign_cell(
                        || format!("gc_table[0]"),
                        self.config.gc_table,
                        0,
                        || Ok(F::zero()),
                    )
                } else {
                    (0..last_step_gc)
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("gc_table[{}]", i),
                                self.config.gc_table,
                                i,
                                || Ok(F::from_u128(i as u128)),
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))
                }
            },
        )?;

        layouter.assign_table(
            || "call_index_table",
            |mut table_column| {
                (0..=MAX_CALL_INDEX)
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
                (0..=MAX_LOCALS_SIZE)
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
