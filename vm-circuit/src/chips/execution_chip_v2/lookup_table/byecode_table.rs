use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use crate::witness::static_info::StaticInfo;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed};
use types::Field;

#[derive(Copy, Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: Column<Fixed>,
    pub function_index_column: Column<Fixed>,
    pub pc_column: Column<Fixed>,
    pub opcode_column: Column<Fixed>,
    pub aux0_column: Column<Fixed>,
    pub aux1_column: Column<Fixed>,
}

impl BytecodeLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            module_index_column: meta.fixed_column(),
            function_index_column: meta.fixed_column(),
            pc_column: meta.fixed_column(),
            opcode_column: meta.fixed_column(),
            aux0_column: meta.fixed_column(),
            aux1_column: meta.fixed_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.opcode_column,
            self.aux0_column,
            self.aux1_column,
        ]
    }

    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        let field_elements: Vec<Vec<F>> = static_info
            .bytecode_info
            .iter()
            .map(|row| row.to_fe())
            .collect();
        assign_fixed_table(layouter, self.columns(), &field_elements, "bytecode_table")
    }
}

impl<F: Field> LookupTable<F> for BytecodeLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.columns().into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            "module_index",
            "function_index",
            "pc",
            "opcode",
            "aux0",
            "aux1",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}
