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
use crate::chips::execution_chip::utils::constraint_builder::{mul_exprs, ConditionalLookup};
use crate::chips::execution_chip::ExecutionChip;
use crate::witness::rw_operations::ConvertedRWOperation;
use halo2_base::halo2_proofs::circuit::AssignedCell;
use halo2_base::halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use types::Field;

use crate::chips::execution_chip::lookup_tables::pi_index_table::PIIndexTable;
use crate::chips::execution_chip::lookup_tables::pi_lookup_table::{PILookup, PILookupTable};
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
        let lookup_table = &execution_chip.config.lookup_table;
        let (stack_operations, locals_operations, global_operations) =
            lookup_table.rw_table.assign_table(
                layouter,
                execution_chip.witness.rw_operations.clone(),
                &execution_chip.witness.circuit_config,
            )?;

        lookup_table.input_type_element_table.assign_table(
            layouter,
            execution_chip.witness.input_type_elements.clone().0,
        )?;
        lookup_table
            .bytecode_table
            .assign_table(layouter, &execution_chip.witness.bytecode_table)?;
        lookup_table
            .constant_table
            .assign_table(layouter, execution_chip.witness.constant_table.clone().0)?;
        lookup_table
            .calls_table
            .assign_table(layouter, execution_chip.witness.func_call_table.clone())?;
        lookup_table
            .arith_op_table
            .assign_table(layouter, &execution_chip.witness.arith_operations)?;
        lookup_table
            .call_trace_table
            .assign_table(layouter, execution_chip.witness.call_trace_table.0.clone())?;
        lookup_table.type_instantiation_table.assign_table(
            layouter,
            execution_chip.witness.type_instantiations.0.clone(),
        )?;
        lookup_table.bitwise_table.assign_table(layouter)?;
        lookup_table.pow2_table.assign_table(layouter)?;

        let pi_index_table = lookup_table.pi_index_table.assign_table(layouter)?;
        let pi_cells = lookup_table.pi_table.assign_table(
            layouter,
            execution_chip.public_input.clone(),
            pi_index_table,
        )?;

        Ok((
            stack_operations,
            locals_operations,
            global_operations,
            pi_cells,
        ))
    }

    pub fn tables_height(&self, execution_chip: &ExecutionChip<F>) -> usize {
        let rw_table_height = self.rw_table.tables_height(
            execution_chip.witness.rw_operations.clone(),
            &execution_chip.witness.circuit_config,
        );
        let input_type_element_table_height = self
            .input_type_element_table
            .table_height(&execution_chip.witness.input_type_elements);
        let bytecode_table_height = self
            .bytecode_table
            .table_height(&execution_chip.witness.bytecode_table);
        let constant_table_height = self
            .constant_table
            .table_height::<F>(&execution_chip.witness.constant_table.0);
        let call_trace_table_height = self
            .call_trace_table
            .table_height(&execution_chip.witness.call_trace_table.0);
        let calls_table_height = self
            .calls_table
            .table_height(&execution_chip.witness.func_call_table);
        let arith_op_table_height = self
            .arith_op_table
            .table_height(&execution_chip.witness.arith_operations);
        let type_instantiation_table_height = self
            .type_instantiation_table
            .table_height(&execution_chip.witness.type_instantiations.0);
        let bitwise_table_height = self.bitwise_table.table_height();
        let pow2_table_height = self.pow2_table.table_height();
        let pi_index_table_height = self.pi_index_table.table_height();
        let pi_table_height = self.pi_table.table_height();

        vec![
            rw_table_height,
            input_type_element_table_height,
            bytecode_table_height,
            constant_table_height,
            call_trace_table_height,
            calls_table_height,
            arith_op_table_height,
            type_instantiation_table_height,
            bitwise_table_height,
            pow2_table_height,
            pi_index_table_height,
            pi_table_height,
        ]
        .into_iter()
        .max()
        .unwrap()
    }
}
