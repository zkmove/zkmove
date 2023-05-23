// Copyright (c) zkMove Authors
use crate::chips::execution_chip::lookup_tables::arith_op_lookup_table::{
    ArithOpLookup, ArithOpLookupTable,
};
use crate::chips::execution_chip::lookup_tables::bitwise_lookup_table::{
    BitwiseLookup, BitwiseLookupTable,
};
use crate::chips::execution_chip::lookup_tables::bytecode_lookup_table::{
    BytecodeLookup, BytecodeLookupTable,
};
use crate::chips::execution_chip::lookup_tables::call_lookup_table::{CallLookup, CallLookupTable};
use crate::chips::execution_chip::lookup_tables::call_trace_table::{
    CallTraceLookup, CallTraceTable,
};
use crate::chips::execution_chip::lookup_tables::input_type_element_table::{
    InputTypeElementLookup, InputTypeElementTable,
};
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::{Pow2FixedTable, Pow2Lookup};
use crate::chips::execution_chip::lookup_tables::rw_table::{RWLookup, RWTable};
use crate::chips::execution_chip::lookup_tables::type_instantiation_table::{
    TypeInstantiationLookup, TypeInstantiationTable,
};
use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::ExecutionChip;
use crate::witness::rw_operations::ConvertedRWOperation;
use halo2_proofs::circuit::Region;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use logger::prelude::*;
use std::marker::PhantomData;

pub mod arith_op_lookup_table;
pub mod bitwise_lookup_table;
pub mod bytecode_lookup_table;
pub mod call_lookup_table;
pub mod call_trace_table;
pub mod input_type_element_table;
pub mod pow2_fixed_table;
pub mod rw_table;
pub mod type_instantiation_table;
pub mod utils;

#[derive(Default)]
pub struct LookupsWithCondition<F: FieldExt> {
    pub rw_lookups: Vec<(&'static str, RWLookup<F>, /*condition*/ Expression<F>)>,
    pub bytecode_lookups: Vec<(
        &'static str,
        BytecodeLookup<F>,
        /*condition*/ Expression<F>,
    )>,
    pub call_lookups: Vec<(
        &'static str,
        CallLookup<F>,
        /*condition*/ Expression<F>,
    )>,
    pub arith_op_lookups: Vec<(
        &'static str,
        ArithOpLookup<F>,
        /*condition*/ Expression<F>,
    )>,
    pub bitwise_lookups: Vec<(
        &'static str,
        BitwiseLookup<F>,
        /*condition*/ Expression<F>,
    )>,
    pub pow2_lookups: Vec<(&'static str, Pow2Lookup<F>, Expression<F>)>,
    pub call_trace_lookups: Vec<(&'static str, CallTraceLookup<F>, Expression<F>)>,
    pub type_instantiation_type_lookups:
        Vec<(&'static str, TypeInstantiationLookup<F>, Expression<F>)>,
    pub input_type_element_lookups: Vec<(&'static str, InputTypeElementLookup<F>, Expression<F>)>,
}

impl<F: FieldExt> LookupsWithCondition<F> {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub struct LookupTableConfig<F: FieldExt> {
    pub rw_table: RWTable,
    pub bytecode_table: BytecodeLookupTable,
    pub calls_table: CallLookupTable,
    pub arith_op_table: ArithOpLookupTable,
    pub bitwise_table: BitwiseLookupTable,
    pub pow2_table: Pow2FixedTable,
    pub call_trace_table: CallTraceTable,
    pub type_instantiation_table: TypeInstantiationTable,
    pub input_type_element_table: InputTypeElementTable,
    _marker: PhantomData<F>,
}
impl<F: FieldExt> LookupTableConfig<F> {
    pub fn construct(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_table = RWTable::construct(meta);
        let bytecode_table = BytecodeLookupTable::construct(meta);
        let calls_table = CallLookupTable::construct(meta);
        let arith_op_table = ArithOpLookupTable::construct(meta);
        let bitwise_table = BitwiseLookupTable::construct(meta);
        let pow2_table = Pow2FixedTable::construct(meta);
        let call_trace_table = CallTraceTable::construct(meta);
        let type_instantiation_table = TypeInstantiationTable::construct(meta);
        let input_type_element_table = InputTypeElementTable::construct(meta);
        LookupTableConfig {
            rw_table,
            bytecode_table,
            calls_table,
            arith_op_table,
            bitwise_table,
            pow2_table,
            call_trace_table,
            type_instantiation_table,
            input_type_element_table,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lookups: &LookupsWithCondition<F>,
        s_step: Selector,
    ) -> LookupTableConfig<F> {
        let lookup_table = Self::construct(meta);

        // for (i, item) in lookups.rw_lookups.iter().enumerate() {
        //     debug!("rw lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.rw_lookups {
            meta.lookup_any(name, |meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.gc.clone() * cond.clone(),
                        meta.query_advice(lookup_table.rw_table.gc_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.rw_target.clone() * cond.clone(),
                        meta.query_advice(lookup_table.rw_table.rw_target_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.rw.clone() * cond.clone(),
                        meta.query_advice(lookup_table.rw_table.rw_column, Rotation::cur()),
                    ),
                    (
                        s_step.clone() * lookup.frame_index.clone() * cond.clone(),
                        meta.query_advice(
                            lookup_table.rw_table.frame_index_column,
                            Rotation::cur(),
                        ),
                    ),
                    (
                        s_step.clone() * lookup.address.clone() * cond.clone(),
                        meta.query_advice(lookup_table.rw_table.address_column, Rotation::cur()),
                    ),
                    (
                        s_step * lookup.value.clone() * cond.clone(),
                        meta.query_advice(lookup_table.rw_table.value_column, Rotation::cur()),
                    ),
                ]
            });
        }

        // for (i, item) in lookups.bytecode_lookups.iter().enumerate() {
        //     debug!("bytecode lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.bytecode_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.module_index.clone() * cond.clone(),
                        lookup_table.bytecode_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index.clone() * cond.clone(),
                        lookup_table.bytecode_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc.clone() * cond.clone(),
                        lookup_table.bytecode_table.pc_column,
                    ),
                    (
                        s_step.clone() * lookup.opcode.clone() * cond.clone(),
                        lookup_table.bytecode_table.opcode_column,
                    ),
                    (
                        s_step * lookup.operand.clone() * cond.clone(),
                        lookup_table.bytecode_table.operand_column,
                    ),
                ]
            });
        }

        // for (i, item) in lookups.call_lookups.iter().enumerate() {
        //     debug!("call lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.call_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.type_.clone() * cond.clone(),
                        lookup_table.calls_table.type_column,
                    ),
                    (
                        s_step.clone() * lookup.module_index.clone() * cond.clone(),
                        lookup_table.calls_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index.clone() * cond.clone(),
                        lookup_table.calls_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc.clone() * cond.clone(),
                        lookup_table.calls_table.pc_column,
                    ),
                    (
                        s_step.clone() * lookup.next_module_index.clone() * cond.clone(),
                        lookup_table.calls_table.callee_module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.next_function_index.clone() * cond.clone(),
                        lookup_table.calls_table.callee_function_index_column,
                    ),
                    (
                        s_step * lookup.next_pc.clone() * cond.clone(),
                        lookup_table.calls_table.next_pc_column,
                    ),
                ]
            });
        }
        for (name, lookup, cond) in &lookups.call_trace_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                lookup
                    .expressions()
                    .into_iter()
                    .map(|e| s_step.clone() * cond.clone() * e)
                    .zip(lookup_table.call_trace_table.columns())
                    .collect()
            });
        }
        for (name, lookup, cond) in &lookups.type_instantiation_type_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                lookup
                    .expressions()
                    .into_iter()
                    .map(|e| s_step.clone() * cond.clone() * e)
                    .zip(lookup_table.type_instantiation_table.columns())
                    .collect()
            });
        }
        for (name, lookup, cond) in &lookups.input_type_element_lookups {
            meta.lookup_any(name, |meta| {
                let s_step = meta.query_selector(s_step);
                lookup
                    .expressions()
                    .into_iter()
                    .map(|e| s_step.clone() * cond.clone() * e)
                    .zip(
                        lookup_table
                            .input_type_element_table
                            .columns()
                            .into_iter()
                            .map(|c| meta.query_advice(c, Rotation::cur())),
                    )
                    .collect()
            });
        }

        // for (i, item) in lookups.arith_op_lookups.iter().enumerate() {
        //     debug!("arith lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.arith_op_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.module_index.clone() * cond.clone(),
                        lookup_table.arith_op_table.module_index_column,
                    ),
                    (
                        s_step.clone() * lookup.function_index.clone() * cond.clone(),
                        lookup_table.arith_op_table.function_index_column,
                    ),
                    (
                        s_step.clone() * lookup.pc.clone() * cond.clone(),
                        lookup_table.arith_op_table.pc_column,
                    ),
                    (
                        s_step * lookup.num_of_bytes.clone() * cond.clone(),
                        lookup_table.arith_op_table.num_of_bytes_column,
                    ),
                ]
            });
        }

        // for (i, item) in lookups.bitwise_lookups.iter().enumerate() {
        //      debug!("bitwise lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.bitwise_lookups {
            meta.lookup(name, |meta| {
                let s_step = meta.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.opcode.clone() * cond.clone(),
                        lookup_table.bitwise_table.opcode_column,
                    ),
                    (
                        s_step.clone() * lookup.value_1.clone() * cond.clone(),
                        lookup_table.bitwise_table.value_1_column,
                    ),
                    (
                        s_step.clone() * lookup.value_2.clone() * cond.clone(),
                        lookup_table.bitwise_table.value_2_column,
                    ),
                    (
                        s_step * lookup.result.clone() * cond.clone(),
                        lookup_table.bitwise_table.result_column,
                    ),
                ]
            });
        }

        // for (i, item) in lookups.pow2_lookups.iter().enumerate() {
        //      debug!("pow2 lookup {}, {:?}", i, item);
        // }
        for (name, lookup, cond) in &lookups.pow2_lookups {
            meta.lookup(name, |vcells| {
                let s_step = vcells.query_selector(s_step);
                vec![
                    (
                        s_step.clone() * lookup.pow.clone() * cond.clone(),
                        lookup_table.pow2_table.pow_column,
                    ),
                    (
                        s_step * lookup.pow_result.clone() * cond.clone(),
                        lookup_table.pow2_table.pow_result_column,
                    ),
                ]
            });
        }

        lookup_table
    }

    #[allow(clippy::type_complexity)]
    pub fn assign(
        layouter: &mut impl Layouter<F>,
        execution_chip: &ExecutionChip<F>,
    ) -> Result<
        (
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
        ),
        Error,
    > {
        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) =
            execution_chip.witness.rw_operations.clone().into();
        let mut stack_operations: Vec<ConvertedRWOperation<F>> = (&sorted_stack_ops).into();
        let mut locals_operations: Vec<ConvertedRWOperation<F>> = (&sorted_locals_ops).into();
        let mut global_operations: Vec<ConvertedRWOperation<F>> = (&sorted_global_ops).into();

        let lookup_table = &execution_chip.config.lookup_table;
        for (column_idx, column) in lookup_table.rw_table.columns().into_iter().enumerate() {
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
                    Self::assign_rw_ops(&mut region, column_idx, column, 0, &mut stack_operations)?;
                    // assign locals operations after stack operations
                    Self::assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len(),
                        &mut locals_operations,
                    )?;
                    // assign global operations after locals operations
                    Self::assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len() + locals_operations.len(),
                        &mut global_operations,
                    )
                },
            )?;
        }
        lookup_table.input_type_element_table.assign_table(
            layouter,
            execution_chip.witness.input_type_elements.clone().0,
        )?;

        let bytecodes: Vec<Vec<F>> = (&execution_chip.witness.bytecode_table).into();
        let bytecode_table_columns = lookup_table.bytecode_table.columns();
        assign_table(
            layouter,
            bytecode_table_columns,
            &bytecodes,
            "bytecode_table",
        )?;

        let func_calls = &execution_chip
            .witness
            .func_calls
            .iter()
            .map(|call| call.into())
            .collect();
        let call_table_columns = lookup_table.calls_table.columns();
        assign_table(layouter, call_table_columns, func_calls, "call_table")?;

        let arith_ops = &execution_chip
            .witness
            .arith_operations
            .iter()
            .map(|op| op.into())
            .collect();
        let arith_op_table_columns = lookup_table.arith_op_table.columns();
        assign_table(
            layouter,
            arith_op_table_columns,
            arith_ops,
            "arith_op_table",
        )?;

        lookup_table
            .call_trace_table
            .assign_table(layouter, execution_chip.witness.call_trace_table.0.clone())?;
        lookup_table.type_instantiation_table.assign_table(
            layouter,
            execution_chip.witness.type_instantiations.0.clone(),
        )?;

        // bitwise table
        // only 4 bits bitwised every time. so table size is 16*16
        let mut bitwise_values = Vec::new();
        for op in [Opcode::BitAnd, Opcode::BitOr, Opcode::Xor] {
            for value_1 in 0..16 {
                for value_2 in 0..16 {
                    let field_values = vec![
                        F::from_u128(op.index() as u128),
                        F::from_u128(value_1 as u128),
                        F::from_u128(value_2 as u128),
                        match op {
                            Opcode::BitAnd => F::from_u128((value_1 & value_2) as u128),
                            Opcode::BitOr => F::from_u128((value_1 | value_2) as u128),
                            Opcode::Xor => F::from_u128((value_1 ^ value_2) as u128),
                            _ => unreachable!(),
                        },
                    ];
                    bitwise_values.push(field_values);
                }
            }
        }
        let bitwise_table_columns = lookup_table.bitwise_table.columns();
        assign_table(
            layouter,
            bitwise_table_columns,
            &bitwise_values,
            "bitwise_table",
        )?;
        lookup_table.pow2_table.assign_table(layouter)?;

        Ok((stack_operations, locals_operations, global_operations))
    }

    pub(crate) fn assign_rw_ops(
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
}
