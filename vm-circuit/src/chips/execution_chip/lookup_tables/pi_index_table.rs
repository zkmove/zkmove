use crate::chips::execution_chip::lookup_tables::pi_lookup_table::PILookupTable;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Fixed};
use types::Field;

#[derive(Clone, Debug)]
pub struct PIIndexTable {
    pub index_column: Column<Fixed>,
}
impl PIIndexTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let index_column = meta.fixed_column();
        meta.enable_equality(index_column);
        Self { index_column }
    }

    // NOTICE: table height must be consistent with assign_table()
    pub fn table_height(&self) -> usize {
        PILookupTable::num_of_rows()
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let pi_index_cells = layouter.assign_region(
            || "pi_index_table",
            |mut region| {
                let mut cells = Vec::new();
                for i in 0..PILookupTable::num_of_rows() {
                    let cell = region.assign_fixed(
                        || format!("pi_index_table[{}]", i),
                        self.index_column,
                        i,
                        || Value::known(F::from_u128(i as u128)),
                    )?;

                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        Ok(pi_index_cells)
    }
}
