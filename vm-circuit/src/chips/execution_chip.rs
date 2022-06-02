// Copyright (c) zkMove Authors

use crate::witness::Witness;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use logger::prelude::*;
use lookup_tables::{BytecodeLookupTable, RWTable};
use step_chip::{StepChip, StepConfig};
use step_chip::{STEP_CHIP_WIDTH, STEP_HEIGHT};

pub mod instructions;
pub mod lookup_tables;
pub mod opcode;
pub mod step_chip;

#[derive(Clone, Debug)]
pub struct ExecutionChipConfig<F: FieldExt> {
    step_config: StepConfig<F>,
    rw_table: RWTable,
    bytecode_table: BytecodeLookupTable,
}

#[derive(Clone, Debug)]
pub struct ExecutionChip<F: FieldExt> {
    pub witness: Witness<F>,
    pub config: ExecutionChipConfig<F>,
}

impl<F: FieldExt> Chip<F> for ExecutionChip<F> {
    type Config = ExecutionChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ExecutionChip<F> {
    pub fn construct(
        witness: Witness<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self { witness, config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        let rw_table = RWTable::construct(meta);
        let bytecode_table = BytecodeLookupTable::construct(meta);
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());
        let step_config = StepChip::configure(meta, advices, &rw_table, &bytecode_table);

        ExecutionChipConfig {
            step_config,
            rw_table,
            bytecode_table,
        }
    }

    pub fn assign(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let step_chip = StepChip::<F>::construct(self.config.step_config.clone(), ());
        let exec_steps = self.witness.process_exec_steps()?;

        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &exec_steps {
                    step_chip.config.s_step.enable(&mut region, offset)?;
                    step_chip.assign(&mut region, offset, step, &self.witness.rw_operations)?;

                    offset += STEP_HEIGHT;
                }
                Ok(())
            },
        )?;

        let (sorted_stack_ops, sorted_locals_ops) = self.witness.rw_operations.clone().into();
        let mut stack_operations: Vec<Vec<Option<F>>> = (&sorted_stack_ops).into();
        let mut locals_operations: Vec<Vec<Option<F>>> = (&sorted_locals_ops).into();
        let mut converted_rw_operations = Vec::new();
        converted_rw_operations.append(&mut stack_operations);
        converted_rw_operations.append(&mut locals_operations);

        for (column_idx, column) in self.config.rw_table.columns().into_iter().enumerate() {
            layouter.assign_region(
                || format!("rw_table[{}]", column_idx),
                |mut region| {
                    region.assign_advice(
                        || format!("rw_table[{}][0]", column_idx),
                        column,
                        0,
                        || Ok(F::zero()),
                    )?;
                    (0..converted_rw_operations.len())
                        .map(|i| {
                            region.assign_advice(
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
                            )?;
                            Ok(())
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))
                },
            )?;
        }

        let converted_bytecodes: Vec<Vec<F>> = (&self.witness.bytecode_table).into();
        for (column_idx, column) in self.config.bytecode_table.columns().into_iter().enumerate() {
            layouter.assign_table(
                || format!("bytecode_table[{}]", column_idx),
                |mut table_column| {
                    table_column.assign_cell(
                        || format!("bytecode_table[{}][0]", column_idx),
                        column,
                        0,
                        || Ok(F::zero()),
                    )?;
                    (0..converted_bytecodes.len())
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("bytecode_table[{}][{}]", column_idx, i),
                                column,
                                i + 1,
                                || {
                                    let bytecode_info =
                                        converted_bytecodes.get(i).ok_or_else(|| {
                                            error!("get bytecode table element error");
                                            Error::Synthesis
                                        })?;
                                    let field = bytecode_info.get(column_idx).ok_or_else(|| {
                                        error!("get bytecode_info_field error");
                                        Error::Synthesis
                                    })?;
                                    Ok(field.clone())
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
