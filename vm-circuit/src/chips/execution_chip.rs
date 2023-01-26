// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookupTable, call_lookup_table::CallLookupTable,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::Witness;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
};
use logger::prelude::*;
use lookup_tables::{
    bitwise_lookup_table::BitwiseLookupTable, bytecode_lookup_table::BytecodeLookupTable,
    rw_table::RWTable,
};
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
    bitwise_table: BitwiseLookupTable,
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
        let bitwise_table = BitwiseLookupTable::construct(meta);
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());
        let step_config = StepChip::configure(
            meta,
            advices,
            &rw_table,
            &bytecode_table,
            &call_table,
            &arith_op_table,
            &bitwise_table,
        );

        ExecutionChipConfig {
            step_config,
            rw_table,
            bytecode_table,
            call_table,
            arith_op_table,
            bitwise_table,
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
                        || CircuitValue::known(F::zero()),
                    )?;

                    // assign stack operations
                    self.assign_rw_ops(&mut region, column_idx, column, 0, &mut stack_operations)?;
                    // assign locals operations after stack operations
                    self.assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len(),
                        &mut locals_operations,
                    )?;
                    // assign global operations after locals operations
                    self.assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len() + locals_operations.len(),
                        &mut global_operations,
                    )
                },
            )?;
        }

        let bytecodes: Vec<Vec<F>> = (&self.witness.bytecode_table).into();
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

        // bitwise table
        // only 4 bits bitwised every time. so table size is 16*16
        let mut bitwise_values = Vec::new();
        for value_1 in 0..16 {
            for value_2 in 0..16 {
                let field_values = vec![
                    F::from_u128(Opcode::BitAnd.index() as u128),
                    F::from_u128(value_1 as u128),
                    F::from_u128(value_2 as u128),
                    F::from_u128((value_1 & value_2) as u128),
                ];
                bitwise_values.push(field_values);
            }
        }
        for value_1 in 0..16 {
            for value_2 in 0..16 {
                let field_values = vec![
                    F::from_u128(Opcode::BitOr.index() as u128),
                    F::from_u128(value_1 as u128),
                    F::from_u128(value_2 as u128),
                    F::from_u128((value_1 | value_2) as u128),
                ];
                bitwise_values.push(field_values);
            }
        }
        for value_1 in 0..16 {
            for value_2 in 0..16 {
                let field_values = vec![
                    F::from_u128(Opcode::Xor.index() as u128),
                    F::from_u128(value_1 as u128),
                    F::from_u128(value_2 as u128),
                    F::from_u128((value_1 ^ value_2) as u128),
                ];
                bitwise_values.push(field_values);
            }
        }
        let bitwise_table_columns = self.config.bitwise_table.columns();
        self.assign_table(
            layouter,
            bitwise_table_columns,
            &bitwise_values,
            "bitwise_table",
        )?;

        Ok((
            last_step_gc_cell,
            stack_operations,
            locals_operations,
            global_operations,
        ))
    }

    fn assign_rw_ops(
        &self,
        region: &mut Region<'_, F>,
        column_idx: usize,
        column: Column<Advice>,
        offset: usize,
        rw_operations: &mut Vec<ConvertedRWOperation<F>>,
    ) -> Result<(), Error> {
        (0..rw_operations.len())
            .map(|i| {
                let op = rw_operations.get_mut(i).ok_or_else(|| {
                    error!("get rw operation error");
                    Error::Synthesis
                })?;
                let field = op.get_field(column_idx).map_err(|e| {
                    error!("get field failed: {:?}", e);
                    Error::Synthesis
                })?;

                let cell = region.assign_advice(
                    || format!("rw_table[{}][{}]", column_idx, offset + i + 1),
                    column,
                    offset + i + 1,
                    || CircuitValue::known(field),
                )?;
                op.assign_cell(column_idx, Some(cell)).map_err(|e| {
                    error!("assign cell failed: {:?}", e);
                    Error::Synthesis
                })
            })
            .fold(Ok(()), |acc, res| acc.and(res))
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
                        || CircuitValue::known(F::zero()),
                    )?;
                    (0..values.len())
                        .map(|i| {
                            table_column.assign_cell(
                                || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                                column,
                                i + 1,
                                || CircuitValue::known(values[i][column_idx]),
                            )
                        })
                        .fold(Ok(()), |acc, res| acc.and(res))
                },
            )?;
        }
        Ok(())
    }
}
