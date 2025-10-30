use crate::lookup_table::utils::assign_fixed_table;
use crate::lookup_table::LookupTable;
use field_exts::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, ErrorFront as Error, Fixed};
use value_type::utils::ToFields;
use witness::static_info::StaticInfo;

#[derive(Copy, Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: Column<Fixed>,
    pub function_index_column: Column<Fixed>,
    pub pc_column: Column<Fixed>,
    pub opcode_column: Column<Fixed>,
    pub operand0_column: Column<Fixed>,
    pub operand1_column: Column<Fixed>,
}

impl BytecodeLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            module_index_column: meta.fixed_column(),
            function_index_column: meta.fixed_column(),
            pc_column: meta.fixed_column(),
            opcode_column: meta.fixed_column(),
            operand0_column: meta.fixed_column(),
            operand1_column: meta.fixed_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.opcode_column,
            self.operand0_column,
            self.operand1_column,
        ]
    }

    pub fn build<F: Field>(&self, static_info: &StaticInfo) -> Vec<Vec<F>> {
        static_info
            .bytecode_info
            .values()
            .flat_map(|row| row.values())
            .flatten()
            .map(|v| v.to_fields())
            .collect()
    }

    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        assign_fixed_table(
            layouter,
            self.columns(),
            &self.build(static_info),
            "bytecode_table",
        )
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
            "operand0",
            "operand1",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}
