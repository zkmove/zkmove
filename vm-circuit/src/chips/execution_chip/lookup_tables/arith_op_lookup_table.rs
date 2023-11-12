use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::arith_operations::ArithOperation;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::{Error, Expression, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct ArithOpLookupTable {
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub num_of_bytes_column: TableColumn,
}
pub const ARITH_OP_LOOKUP_TABLE_WIDTH: usize = 4;

impl ArithOpLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        ArithOpLookupTable {
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            num_of_bytes_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.num_of_bytes_column,
        ]
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        arith_ops: &[ArithOperation],
    ) -> Result<(), Error> {
        let arith_ops = arith_ops.iter().map(|op| op.into()).collect::<Vec<_>>();

        assign_table(layouter, self.columns(), &arith_ops, "arith_op_table")
    }

    pub fn table_height(&self, arith_ops: &Vec<ArithOperation>) -> usize {
        arith_ops.len() + 1
    }
}

#[derive(Clone, Debug)]
pub struct ArithOpLookup<F: Field> {
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub num_of_bytes: Expression<F>,
}

impl<F: Field> ArithOpLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.module_index.clone(),
            self.function_index.clone(),
            self.pc.clone(),
            self.num_of_bytes.clone(),
        ]
    }
}
