use halo2_proofs::plonk::{Expression, TableColumn};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct BitwiseLookupTable {
    pub opcode_column: TableColumn,
    pub value_1_column: TableColumn,
    pub value_2_column: TableColumn,
    pub result_column: TableColumn,
}
pub const BITWISE_LOOKUP_TABLE_WIDTH: usize = 4;

impl BitwiseLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        BitwiseLookupTable {
            opcode_column: meta.lookup_table_column(),
            value_1_column: meta.lookup_table_column(),
            value_2_column: meta.lookup_table_column(),
            result_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.opcode_column,
            self.value_1_column,
            self.value_2_column,
            self.result_column,
        ]
    }
}

pub struct BitwiseLookup<F: FieldExt> {
    pub opcode: Expression<F>,
    pub value_1: Expression<F>,
    pub value_2: Expression<F>,
    pub result: Expression<F>,
}
