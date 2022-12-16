// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookupTable, call_lookup_table::CallLookupTable,
};
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::Witness;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::TableColumn;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use logger::prelude::*;
use lookup_tables::{bytecode_lookup_table::BytecodeLookupTable, rw_table::RWTable};
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
    call_table: CallLookupTable,
    arith_op_table: ArithOpLookupTable,
}

#[derive(Clone, Debug)]
pub struct ExecutionChip<F: FieldExt> {
    pub(crate) witness: Witness<F>,
    pub(crate) config: ExecutionChipConfig<F>,
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
        let call_table = CallLookupTable::construct(meta);
        let arith_op_table = ArithOpLookupTable::construct(meta);
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());
        let step_config = StepChip::configure(
            meta,
            advices,
            &rw_table,
            &bytecode_table,
            &call_table,
            &arith_op_table,
        );

        ExecutionChipConfig {
            step_config,
            rw_table,
            bytecode_table,
            call_table,
            arith_op_table,
        }
    }

    // return assigned cells for 1.last_step_gc, 2.sorted_stack_ops, 3.sorted_locals_ops
    // 4. sorted_global_ops
    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<
        (
            Option<AssignedCell<F, F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
        ),
        Error,
    > {
        let step_chip = StepChip::<F>::construct(self.config.step_config.clone(), ());
        let exec_steps = self.witness.process_exec_steps()?;
        let mut gc_cell = None;
        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &exec_steps {
                    step_chip.config.s_step.enable(&mut region, offset)?;
                    gc_cell =
                        step_chip.assign(&mut region, offset, step, &self.witness.rw_operations)?;

                    offset += STEP_HEIGHT;
                }
                Ok(())
            },
        )?;
        let last_step_gc_cell = gc_cell;

        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) =
            self.witness.rw_operations.clone().into();
        let mut stack_operations: Vec<ConvertedRWOperation<F>> = (&sorted_stack_ops).into();
        let mut locals_operations: Vec<ConvertedRWOperation<F>> = (&sorted_locals_ops).into();
        let mut global_operations: Vec<ConvertedRWOperation<F>> = (&sorted_global_ops).into();

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
                    (0..stack_operations.len())
                        .map(|i| {
                            let op = stack_operations.get_mut(i).ok_or_else(|| {
                                error!("get rw operation error");
                                Error::Synthesis
                            })?;
                            let field = op.get_field(column_idx).map_err(|e| {
                                error!("get field failed: {:?}", e);
                                Error::Synthesis
                            })?;

                            let cell = region.assign_advice(
                                || format!("rw_table[{}][{}]", column_idx, i),
                                column,
                                i + 1,
                                || Ok(field),
                            )?;
                            op.assign_cell(column_idx, Some(cell)).map_err(|e| {
                                error!("assign cell failed: {:?}", e);
                                Error::Synthesis
                            })
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))?;

                    (0..locals_operations.len())
                        .map(|i| {
                            let op = locals_operations.get_mut(i).ok_or_else(|| {
                                error!("get rw operation error");
                                Error::Synthesis
                            })?;
                            let field = op.get_field(column_idx).map_err(|e| {
                                error!("get field failed: {:?}", e);
                                Error::Synthesis
                            })?;
                            let cell = region.assign_advice(
                                || {
                                    format!(
                                        "rw_table[{}][{}]",
                                        column_idx,
                                        stack_operations.len() + i
                                    )
                                },
                                column,
                                stack_operations.len() + i + 1,
                                || Ok(field),
                            )?;
                            op.assign_cell(column_idx, Some(cell)).map_err(|e| {
                                error!("assign cell failed: {:?}", e);
                                Error::Synthesis
                            })
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))?;

                    (0..global_operations.len())
                        .map(|i| {
                            let op = global_operations.get_mut(i).ok_or_else(|| {
                                error!("get rw operation error");
                                Error::Synthesis
                            })?;
                            let field = op.get_field(column_idx).map_err(|e| {
                                error!("get field failed: {:?}", e);
                                Error::Synthesis
                            })?;
                            let cell = region.assign_advice(
                                || {
                                    format!(
                                        "rw_table[{}][{}]",
                                        column_idx,
                                        stack_operations.len() + locals_operations.len() + i
                                    )
                                },
                                column,
                                stack_operations.len() + locals_operations.len() + i + 1,
                                || Ok(field),
                            )?;
                            op.assign_cell(column_idx, Some(cell)).map_err(|e| {
                                error!("assign cell failed: {:?}", e);
                                Error::Synthesis
                            })?;
                            Ok(())
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))
                },
            )?;
        }

        let bytecodes = self
            .witness
            .bytecode_table
            .as_inner()
            .iter()
            .map(|bytecode_info| bytecode_info.into())
            .collect::<Vec<_>>();
        let bytecode_table_columns = self.config.bytecode_table.columns();
        self.assign_table(
            layouter,
            bytecode_table_columns,
            &bytecodes,
            "bytecode_table",
        )?;

        let func_calls = &self
            .witness
            .func_calls
            .iter()
            .map(|call| call.into())
            .collect();
        let call_table_columns = self.config.call_table.columns();
        self.assign_table(layouter, call_table_columns, func_calls, "call_table")?;

        let arith_ops = &self
            .witness
            .arith_operations
            .iter()
            .map(|op| op.into())
            .collect();
        let arith_op_table_columns = self.config.arith_op_table.columns();
        self.assign_table(
            layouter,
            arith_op_table_columns,
            arith_ops,
            "arith_op_table",
        )?;

        Ok((
            last_step_gc_cell,
            stack_operations,
            locals_operations,
            global_operations,
        ))
    }

    fn assign_table(
        &self,
        layouter: &mut impl Layouter<F>,
        table_columns: Vec<TableColumn>,
        values: &Vec<Vec<F>>,
        table_name: &str,
    ) -> Result<(), Error> {
        for (column_idx, column) in table_columns.into_iter().enumerate() {
            layouter.assign_table(
                || format!("{:?}[{}]", table_name, column_idx),
                |mut table_column| {
                    table_column.assign_cell(
                        || format!("{:?}[{}][0]", table_name, column_idx),
                        column,
                        0,
                        || Ok(F::zero()),
                    )?;
                    (0..values.len())
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                                column,
                                i + 1,
                                || {
                                    // let op: Vec<F> = values[i];
                                    // Ok(op[column_idx])
                                    Ok(values[i][column_idx])
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
