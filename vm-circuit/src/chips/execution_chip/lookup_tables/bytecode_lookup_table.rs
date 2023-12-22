use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::bytecode_table::BytecodeTable;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::plonk::{Error, Expression, TableColumn};
use types::Field;

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
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
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

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecode_table: &BytecodeTable,
    ) -> Result<(), Error> {
        let bytecodes: Vec<Vec<F>> = bytecode_table.into();
        assign_table(layouter, self.columns(), &bytecodes, "bytecode_table")
    }

    pub fn table_height(&self, bytecode_table: &BytecodeTable) -> usize {
        bytecode_table.as_inner().len() + 1
    }
}

#[derive(Clone, Debug)]
pub struct BytecodeLookup<F: Field> {
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub opcode: Expression<F>,
    pub operand2: Expression<F>,
    pub operand: Expression<F>,
}

impl<F: Field> BytecodeLookup<F> {
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
