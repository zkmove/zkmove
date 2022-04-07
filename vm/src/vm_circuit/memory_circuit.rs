// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::lookup_tables::RWTable;
use crate::vm_circuit::chips::stack_op_chip::{StackOpChip, StackOpChipConfig};
use crate::vm_circuit::circuit_inputs::CircuitInputs;
use halo2_proofs::circuit::Region;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;

pub const MEM_CIRCUIT_WIDTH: usize = 5;

#[derive(Clone)]
pub struct MemoryCircuitConfig<F: FieldExt> {
    stack_op_config: StackOpChipConfig<F>,
    rw_table: RWTable,
}

#[derive(Clone, Default)]
pub struct MemoryCircuit<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
}

impl<F: FieldExt> Circuit<F> for MemoryCircuit<F> {
    type Config = MemoryCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rw_table = RWTable::construct(meta);
        let advices = [(); MEM_CIRCUIT_WIDTH].map(|_| meta.advice_column());
        let stack_op_config = StackOpChip::configure(meta, advices, &rw_table);

        Self::Config {
            stack_op_config,
            rw_table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let stack_op_chip = StackOpChip::<F>::construct(config.stack_op_config, ());

        layouter.assign_region(
            || "stack operations",
            |mut region: Region<'_, F>| {
                for (offset, op) in self.circuit_inputs.sorted_stack_ops.0.iter().enumerate() {
                    if offset == 0 {
                        stack_op_chip
                            .config
                            .s_first_stack_op
                            .enable(&mut region, offset)?;
                        stack_op_chip.assign(&mut region, offset, op)?;
                    } else {
                        stack_op_chip
                            .config
                            .s_stack_op
                            .enable(&mut region, offset)?;
                        stack_op_chip.assign(&mut region, offset, op)?;
                    }
                }
                Ok(())
            },
        )?;

        let rw_operations = &self.circuit_inputs.rw_lookup_table.0;
        for (column_idx, column) in config.rw_table.columns().into_iter().enumerate() {
            layouter.assign_table(
                || format!("rw_table[{}]", column_idx),
                |mut table_column| {
                    table_column.assign_cell(
                        || format!("rw_table[{}][0]", column_idx),
                        column,
                        0,
                        || Ok(F::zero()),
                    )?;
                    (0..rw_operations.len())
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("rw_table[{}][{}]", column_idx, i),
                                column,
                                i + 1,
                                || {
                                    let op = rw_operations.get(i).ok_or_else(|| {
                                        error!("get rw operation error");
                                        Error::Synthesis
                                    })?;
                                    let op_fields: Vec<Option<F>> = op.into();
                                    let field = op_fields.get(column_idx).ok_or_else(|| {
                                        error!("get op_field error");
                                        Error::Synthesis
                                    })?;
                                    field.ok_or_else(|| {
                                        error!("rw operation field[{}] is None", column_idx);
                                        Error::Synthesis
                                    })
                                },
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))
                },
            )?;
        }

        Ok(())
    }
}
