// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::chips::execution_chip_v2::utils::to_field::ToFields;
use crate::table::LookupTable;
use aptos_move_witnesses::static_info::function::FunctionInfo;
use aptos_move_witnesses::static_info::StaticInfo;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed};
use itertools::Itertools;
use types::Field;

/// Function handle table of all dependent modules, which include handles to
/// external and internal functions of each module.
#[derive(Clone, Copy, Debug)]
pub struct FunctionLookupTable {
    pub module_index_column: Column<Fixed>,
    pub function_handle_index_column: Column<Fixed>,
    pub def_module_index_column: Column<Fixed>, // index of the module that defines the function
    pub function_index_column: Column<Fixed>,   // index of function definition
    pub num_arg_column: Column<Fixed>,
    pub entry: Column<Fixed>, // is entry function
}

impl FunctionLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        FunctionLookupTable {
            module_index_column: meta.fixed_column(),
            function_handle_index_column: meta.fixed_column(),
            def_module_index_column: meta.fixed_column(),
            function_index_column: meta.fixed_column(),
            num_arg_column: meta.fixed_column(),
            entry: meta.fixed_column(),
        }
    }
    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![
            self.module_index_column,
            self.function_handle_index_column,
            self.def_module_index_column,
            self.function_index_column,
            self.num_arg_column,
            self.entry,
        ]
    }
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        let rows = static_info
            .function_info
            .iter()
            .map(|func_info| FunctionTableRow::from(func_info))
            .unique()
            .collect::<Vec<_>>();

        // load entry function. by default, each normal function occupies one row with column
        // 'entry' == 0. Entry function has an additional row with column 'entry' == 1.
        let entry = static_info
            .get_entry_function(
                static_info.entry.module_index,
                static_info.entry.function_index,
            )
            .unwrap_or_else(|| panic!("cannot find entry"));
        let row_entry = FunctionTableRow {
            module_index: entry.module_index,
            function_handle_index: entry.function_handle_index,
            def_module_index: entry.def_module_index,
            function_index: entry.function_index,
            num_arg: entry.num_arg(),
            entry: true,
        };

        let field_elements: Vec<Vec<F>> = rows
            .into_iter()
            .chain(vec![row_entry])
            .map(|row| row.to_fields())
            .collect();
        assign_fixed_table(layouter, self.columns(), &field_elements, "function_table")
    }
}

impl<F: Field> LookupTable<F> for FunctionLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.columns().into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            "module_index",
            "function_handle_index",
            "def_module_index",
            "function_index",
            "num_arg",
            "entry",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FunctionTableRow {
    pub module_index: usize,
    pub function_handle_index: usize,
    pub def_module_index: usize,
    pub function_index: usize,
    pub num_arg: usize,
    pub entry: bool,
}

impl From<&FunctionInfo> for FunctionTableRow {
    fn from(func: &FunctionInfo) -> Self {
        Self {
            module_index: func.def_module_index,
            function_handle_index: func.function_handle_index,
            def_module_index: func.def_module_index,
            function_index: func.function_index,
            num_arg: func.num_arg,
            entry: false,
        }
    }
}
