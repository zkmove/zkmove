use halo2_proofs::plonk::{Expression, TableColumn};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub opcode_column: TableColumn,
    pub operand2_column: TableColumn, // add for u256 upper 128 bit.
    pub operand_column: TableColumn,
}
pub const BYTECODE_LOOKUP_TABLE_WIDTH: usize = 6;

impl BytecodeLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        BytecodeLookupTable {
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            opcode_column: meta.lookup_table_column(),
            operand2_column: meta.lookup_table_column(),
            operand_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.opcode_column,
            self.operand2_column,
            self.operand_column,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct BytecodeLookup<F: FieldExt> {
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub opcode: Expression<F>,
    pub operand2: Expression<F>,
    pub operand: Expression<F>,
}

impl<F: FieldExt> BytecodeLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.module_index.clone(),
            self.function_index.clone(),
            self.pc.clone(),
            self.opcode.clone(),
            self.operand2.clone(),
            self.operand.clone(),
        ]
    }
}
