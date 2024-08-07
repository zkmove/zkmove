// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use crate::witness::static_info::StaticInfo;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed};
use types::Field;

/// Function handle table of all dependent modules, which include handles to
/// external and internal functions of each module.
#[derive(Clone, Debug)]
pub struct FunctionLookupTable {
    pub module_index_column: Column<Fixed>,
    pub function_handle_index_column: Column<Fixed>,
    pub def_module_index_column: Column<Fixed>, // index of the module that defines the function
    pub function_index_column: Column<Fixed>,   // index of function definition
    pub num_arg_column: Column<Fixed>,
}

impl FunctionLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        FunctionLookupTable {
            module_index_column: meta.fixed_column(),
            function_handle_index_column: meta.fixed_column(),
            def_module_index_column: meta.fixed_column(),
            function_index_column: meta.fixed_column(),
            num_arg_column: meta.fixed_column(),
        }
    }
    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![
            self.module_index_column,
            self.function_handle_index_column,
            self.def_module_index_column,
            self.function_index_column,
            self.num_arg_column,
        ]
    }
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        let field_elements: Vec<Vec<F>> = static_info
            .function_info
            .iter()
            .map(|row| row.to_fe())
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
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}
