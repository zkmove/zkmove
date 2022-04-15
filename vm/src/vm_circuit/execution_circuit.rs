// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::lookup_tables::RWTable;
use crate::vm_circuit::chips::step_chip::{StepChip, StepConfig};
use crate::vm_circuit::chips::step_chip::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::vm_circuit::circuit_inputs::CircuitInputs;
use halo2_proofs::circuit::Region;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;

#[derive(Clone)]
pub struct ExecutionCircuitConfig<F: FieldExt> {
    step_config: StepConfig<F>,
    rw_table: RWTable,
}

#[derive(Clone, Default)]
pub struct ExecutionCircuit<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
}

impl<F: FieldExt> Circuit<F> for ExecutionCircuit<F> {
    type Config = ExecutionCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rw_table = RWTable::construct(meta);
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());
        let step_config = StepChip::configure(meta, advices, &rw_table);

        Self::Config {
            step_config,
            rw_table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let step_chip = StepChip::<F>::construct(config.step_config, ());

        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &self.circuit_inputs.exec_steps {
                    step_chip.config.s_step.enable(&mut region, offset)?;
                    step_chip.assign(
                        &mut region,
                        offset,
                        step,
                        &self.circuit_inputs.rw_lookup_table,
                    )?;

                    offset += STEP_HEIGHT;
                }
                Ok(())
            },
        )?;

        let mut stack_operations: Vec<Vec<Option<F>>> =
            (&self.circuit_inputs.sorted_stack_ops).into();
        let mut locals_operations: Vec<Vec<Option<F>>> =
            (&self.circuit_inputs.sorted_locals_ops).into();
        let mut converted_rw_operations = Vec::new();
        converted_rw_operations.append(&mut stack_operations);
        converted_rw_operations.append(&mut locals_operations);

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
                    (0..converted_rw_operations.len())
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("rw_table[{}][{}]", column_idx, i),
                                column,
                                i + 1,
                                || {
                                    let op = converted_rw_operations.get(i).ok_or_else(|| {
                                        error!("get rw operation error");
                                        Error::Synthesis
                                    })?;
                                    let field = op.get(column_idx).ok_or_else(|| {
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
