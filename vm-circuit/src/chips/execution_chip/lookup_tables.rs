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
use crate::chips::execution_chip::lookup_tables::constant_lookup_table::{
    ConstantLookup, ConstantLookupTable,
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
use crate::chips::execution_chip::utils::constraint_builder::{mul_exprs, ConditionalLookup};
use crate::chips::execution_chip::ExecutionChip;
use crate::witness::rw_operations::ConvertedRWOperation;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use types::Field;

use crate::chips::execution_chip::lookup_tables::pi_index_table::PIIndexTable;
use crate::chips::execution_chip::lookup_tables::pi_lookup_table::{PILookup, PILookupTable};
use logger::prelude::*;
use std::collections::BTreeMap;
use std::marker::PhantomData;

pub mod arith_op_lookup_table;
pub mod bitwise_lookup_table;
pub mod bytecode_lookup_table;
pub mod call_lookup_table;
pub mod call_trace_table;
pub mod constant_lookup_table;
pub mod input_type_element_table;
mod pi_index_table;
pub mod pi_lookup_table;
pub mod pow2_fixed_table;
pub mod rw_table;
pub mod type_instantiation_table;
pub mod utils;

#[derive(Clone, Debug)]
pub enum Lookup<F: Field> {
    RW(RWLookup<F>),
    MoveConstant(ConstantLookup<F>),
    Bytecode(BytecodeLookup<F>),
    Call(CallLookup<F>),
    ArithOp(ArithOpLookup<F>),
    Bitwise(BitwiseLookup<F>),
    Pow2(Pow2Lookup<F>),
    CallTrace(CallTraceLookup<F>),
    TypeInstantiation(TypeInstantiationLookup<F>),
    InputTypeArg(InputTypeElementLookup<F>),
    PI(PILookup<F>),
}

impl<F: Field> From<BytecodeLookup<F>> for Lookup<F> {
    fn from(l: BytecodeLookup<F>) -> Self {
        Self::Bytecode(l)
    }
}
impl<F: Field> From<RWLookup<F>> for Lookup<F> {
    fn from(l: RWLookup<F>) -> Self {
        Self::RW(l)
    }
}
impl<F: Field> From<ConstantLookup<F>> for Lookup<F> {
    fn from(l: ConstantLookup<F>) -> Self {
        Self::MoveConstant(l)
    }
}
impl<F: Field> From<CallLookup<F>> for Lookup<F> {
    fn from(l: CallLookup<F>) -> Self {
        Self::Call(l)
    }
}

impl<F: Field> From<ArithOpLookup<F>> for Lookup<F> {
    fn from(l: ArithOpLookup<F>) -> Self {
        Self::ArithOp(l)
    }
}

impl<F: Field> From<BitwiseLookup<F>> for Lookup<F> {
    fn from(l: BitwiseLookup<F>) -> Self {
        Self::Bitwise(l)
    }
}

impl<F: Field> From<Pow2Lookup<F>> for Lookup<F> {
    fn from(l: Pow2Lookup<F>) -> Self {
        Self::Pow2(l)
    }
}
impl<F: Field> From<CallTraceLookup<F>> for Lookup<F> {
    fn from(l: CallTraceLookup<F>) -> Self {
        Self::CallTrace(l)
    }
}
impl<F: Field> From<TypeInstantiationLookup<F>> for Lookup<F> {
    fn from(l: TypeInstantiationLookup<F>) -> Self {
        Self::TypeInstantiation(l)
    }
}
impl<F: Field> From<InputTypeElementLookup<F>> for Lookup<F> {
    fn from(l: InputTypeElementLookup<F>) -> Self {
        Self::InputTypeArg(l)
    }
}
impl<F: Field> From<PILookup<F>> for Lookup<F> {
    fn from(l: PILookup<F>) -> Self {
        Self::PI(l)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum TableKind {
    RW,
    MoveConstant,
    Bytecode,
    Call,
    ArithOp,
    Bitwise,
    Pow2,
    CallTrace,
    TypeInstantiation,
    InputTypeArg,
    PI,
}

impl<F: Field> Lookup<F> {
    pub fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Lookup::RW(rw) => rw.exprs(),
            Lookup::MoveConstant(c) => c.exprs(),
            Lookup::Bytecode(v) => v.exprs(),
            Lookup::Call(c) => c.exprs(),
            Lookup::ArithOp(l) => l.exprs(),
            Lookup::Bitwise(l) => l.exprs(),
            Lookup::Pow2(l) => l.exprs(),
            Lookup::CallTrace(l) => l.exprs(),
            Lookup::TypeInstantiation(l) => l.exprs(),
            Lookup::InputTypeArg(l) => l.exprs(),
            Lookup::PI(l) => l.exprs(),
        }
    }

    pub fn table(&self) -> TableKind {
        match self {
            Lookup::RW(_) => TableKind::RW,
            Lookup::MoveConstant(_) => TableKind::MoveConstant,
            Lookup::Bytecode(_) => TableKind::Bytecode,
            Lookup::Call(_) => TableKind::Call,
            Lookup::ArithOp(_) => TableKind::ArithOp,
            Lookup::Bitwise(_) => TableKind::Bitwise,
            Lookup::Pow2(_) => TableKind::Pow2,
            Lookup::CallTrace(_) => TableKind::CallTrace,
            Lookup::TypeInstantiation(_) => TableKind::TypeInstantiation,
            Lookup::InputTypeArg(_) => TableKind::InputTypeArg,
            Lookup::PI(_) => TableKind::PI,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LookupTableConfig<F: Field> {
    pub rw_table: RWTable,
    pub constant_table: ConstantLookupTable,
    pub bytecode_table: BytecodeLookupTable,
    pub calls_table: CallLookupTable,
    pub arith_op_table: ArithOpLookupTable,
    pub bitwise_table: BitwiseLookupTable,
    pub pow2_table: Pow2FixedTable,
    pub call_trace_table: CallTraceTable,
    pub type_instantiation_table: TypeInstantiationTable,
    pub input_type_element_table: InputTypeElementTable,
    pub pi_table: PILookupTable,
    pi_index_table: PIIndexTable,
    _marker: PhantomData<F>,
}
impl<F: Field> LookupTableConfig<F> {
    pub fn construct(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_table = RWTable::construct(meta);
        let bytecode_table = BytecodeLookupTable::construct(meta);
        let constant_table = ConstantLookupTable::construct(meta);
        let calls_table = CallLookupTable::construct(meta);
        let arith_op_table = ArithOpLookupTable::construct(meta);
        let bitwise_table = BitwiseLookupTable::construct(meta);
        let pow2_table = Pow2FixedTable::construct(meta);
        let call_trace_table = CallTraceTable::construct(meta);
        let type_instantiation_table = TypeInstantiationTable::construct(meta);
        let input_type_element_table = InputTypeElementTable::construct(meta);
        let pi_table = PILookupTable::construct(meta);
        let pi_index_table = PIIndexTable::construct(meta);
        LookupTableConfig {
            rw_table,
            constant_table,
            bytecode_table,
            calls_table,
            arith_op_table,
            bitwise_table,
            pow2_table,
            call_trace_table,
            type_instantiation_table,
            input_type_element_table,
            pi_table,
            pi_index_table,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        mut lookups: Vec<(&'static str, ConditionalLookup<F>)>,
        s_usable: Selector,
        s_step: Column<Advice>,
    ) -> LookupTableConfig<F> {
        let lookup_table = Self::construct(meta);
        lookups.sort_by_key(|(_, l)| l.as_ref().table());
        // for (kind, ls) in lookups
        //     .iter()
        //     .fold(BTreeMap::default(), |mut r, (name, l)| {
        //         r.entry(l.table()).or_insert(vec![]).push((name, l));
        //         r
        //     })
        //     .iter()
        // {
        //     println!("{:?}", kind);
        //     for (name, l) in ls {
        //         let (conds, exprs) = l.cond_and_exprs();
        //         let cond = mul_exprs(&conds).unwrap();
        //         println!(
        //             "{}, {}",
        //             name,
        //             exprs
        //                 .iter()
        //                 .map(|e| cond.clone() * e.clone())
        //                 .map(|e| format!("{}|{}", e.complexity(), e.degree()))
        //                 .join(","),
        //         );
        //         println!("{}", cond.identifier());
        //         println!("{}", exprs.iter().map(|e| e.identifier()).join(","));
        //     }
        // }

        let mut fixed_tables = BTreeMap::new();
        fixed_tables.insert(
            TableKind::MoveConstant,
            lookup_table.constant_table.columns(),
        );
        fixed_tables.insert(TableKind::Bytecode, lookup_table.bytecode_table.columns());
        fixed_tables.insert(TableKind::Call, lookup_table.calls_table.columns());
        fixed_tables.insert(TableKind::ArithOp, lookup_table.arith_op_table.columns());
        fixed_tables.insert(TableKind::Bitwise, lookup_table.bitwise_table.columns());
        fixed_tables.insert(TableKind::Pow2, lookup_table.pow2_table.columns());
        fixed_tables.insert(
            TableKind::CallTrace,
            lookup_table.call_trace_table.columns(),
        );
        fixed_tables.insert(
            TableKind::TypeInstantiation,
            lookup_table.type_instantiation_table.columns(),
        );
        let mut advice_tables = BTreeMap::new();
        advice_tables.insert(TableKind::RW, lookup_table.rw_table.columns());
        advice_tables.insert(
            TableKind::InputTypeArg,
            lookup_table.input_type_element_table.columns(),
        );
        advice_tables.insert(TableKind::PI, lookup_table.pi_table.columns());

        for (name, mut lookup) in lookups {
            let mut fixed_table_columns = Vec::new();
            let mut advice_table_columns = Vec::new();

            match lookup.as_ref().table() {
                t @ (TableKind::RW | TableKind::InputTypeArg | TableKind::PI) => {
                    advice_table_columns = advice_tables.get(&t).cloned().unwrap();
                }
                t => {
                    fixed_table_columns = fixed_tables.get(&t).cloned().unwrap();
                }
            };
            if !advice_table_columns.is_empty() {
                debug_assert_eq!(
                    advice_table_columns.len(),
                    lookup.as_ref().input_exprs().len()
                );

                meta.lookup_any(name, |meta| {
                    let s_usable = meta.query_selector(s_usable);
                    let s_step = meta.query_advice(s_step, Rotation::cur());
                    lookup.add_conditions(vec![s_usable, s_step]);
                    let (conds, lookup) = lookup.into();

                    let cond = mul_exprs(&conds).unwrap();
                    lookup
                        .input_exprs()
                        .into_iter()
                        .map(|e| cond.clone() * e)
                        .zip(
                            advice_table_columns
                                .into_iter()
                                .map(|col| meta.query_advice(col, Rotation::cur())),
                        )
                        .collect()
                });
            } else {
                debug_assert!(!fixed_table_columns.is_empty());
                debug_assert_eq!(
                    fixed_table_columns.len(),
                    lookup.as_ref().input_exprs().len()
                );

                meta.lookup(name, |meta| {
                    let s_usable = meta.query_selector(s_usable);
                    let s_step = meta.query_advice(s_step, Rotation::cur());
                    lookup.add_conditions(vec![s_usable, s_step]);
                    let (conds, lookup) = lookup.into();
                    let cond = mul_exprs(&conds).unwrap();
                    lookup
                        .input_exprs()
                        .into_iter()
                        .map(|e| cond.clone() * e)
                        .zip(fixed_table_columns)
                        .collect()
                });
            }
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
            Vec<AssignedCell<F, F>>, // pi cells
        ),
        Error,
    > {
        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) =
            execution_chip.witness.rw_operations.clone().into();
        let mut stack_operations: Vec<ConvertedRWOperation<F>> = (&sorted_stack_ops).into();
        let mut locals_operations: Vec<ConvertedRWOperation<F>> = (&sorted_locals_ops).into();
        let mut global_operations: Vec<ConvertedRWOperation<F>> = (&sorted_global_ops).into();
        let stack_ops_num = execution_chip
            .witness
            .circuit_config
            .stack_ops_num
            .unwrap_or(0);
        let locals_ops_num = execution_chip
            .witness
            .circuit_config
            .locals_ops_num
            .unwrap_or(0);
        let global_ops_num = execution_chip
            .witness
            .circuit_config
            .global_ops_num
            .unwrap_or(0);
        debug!(
            "rw_lens, stack: {}, local: {}, global: {}",
            stack_operations.len(),
            locals_operations.len(),
            global_operations.len()
        );
        if stack_ops_num > 0 {
            if stack_operations.len() > stack_ops_num {
                error!(
                    "stack operations length {:?} exceeds stack_ops_num {:?}",
                    stack_operations.len(),
                    stack_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                stack_operations.resize(stack_ops_num, ConvertedRWOperation::empty());
            }
        }
        if locals_ops_num > 0 {
            if locals_operations.len() > locals_ops_num {
                error!(
                    "locals operations length {:?} exceeds locals_ops_num {:?}",
                    locals_operations.len(),
                    locals_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                locals_operations.resize(locals_ops_num, ConvertedRWOperation::empty());
            }
        }
        if global_ops_num > 0 {
            if global_operations.len() > global_ops_num {
                error!(
                    "global operations length {:?} exceeds global_ops_num {:?}",
                    global_operations.len(),
                    global_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                global_operations.resize(global_ops_num, ConvertedRWOperation::empty());
            }
        }
        let lookup_table = &execution_chip.config.lookup_table;
        for (column_idx, column) in lookup_table.rw_table.columns().into_iter().enumerate() {
            layouter.assign_region(
                || format!("rw_table[{}]", column_idx),
                |mut region| {
                    region.assign_advice(
                        || format!("rw_table[{}][0]", column_idx),
                        column,
                        0,
                        || CircuitValue::known(F::ZERO),
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
        lookup_table
            .constant_table
            .assign_table(layouter, execution_chip.witness.constant_table.clone().0)?;

        lookup_table
            .calls_table
            .assign_table(layouter, execution_chip.witness.func_call_table.clone())?;

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

        let pi_index_table = lookup_table.pi_index_table.assign_table(layouter)?;
        let pi_cells = lookup_table.pi_table.assign_table(
            layouter,
            execution_chip.public_input.clone(),
            pi_index_table,
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

        Ok((
            stack_operations,
            locals_operations,
            global_operations,
            pi_cells,
        ))
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
