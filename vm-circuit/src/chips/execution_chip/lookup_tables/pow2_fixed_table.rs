use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct Pow2FixedTable {
    pub pow_column: TableColumn,
    pub pow_result_column: TableColumn,
}
pub const POW2_LOOKUP_TABLE_WIDTH: usize = 2;
impl Pow2FixedTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            pow_column: meta.lookup_table_column(),
            pow_result_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![self.pow_column, self.pow_result_column]
    }

    // NOTICE: table height must be consistent with assign_table()
    pub fn table_height(&self) -> usize {
        128 + 1
    }

    pub fn assign_table<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let rows = (0u32..128)
            .map(|p| vec![F::from_u128(p as u128), F::from_u128(2u128.pow(p))])
            .collect();
        assign_table(layouter, self.columns(), &rows, "pow2_table")?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Pow2Lookup<F: Field> {
    pub pow: Expression<F>,
    pub pow_result: Expression<F>,
}

impl<F: Field> Pow2Lookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![self.pow.clone(), self.pow_result.clone()]
    }
}
