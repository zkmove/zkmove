use crate::chips::execution_chip::param::word_capacity;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Fixed};

#[derive(Clone, Debug)]
pub struct RVRIndexTable {
    pub index_column: Column<Fixed>,
}
impl RVRIndexTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let index_column = meta.fixed_column();
        meta.enable_equality(index_column);
        Self { index_column }
    }

    pub fn assign_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let rvr_index_cells = layouter.assign_region(
            || "rvr_index_table",
            |mut region| {
                let mut cells = Vec::new();
                for i in 0..=word_capacity() {
                    let cell = region.assign_fixed(
                        || format!("rvr_index_table[{}]", i),
                        self.index_column,
                        i,
                        || Value::known(F::from_u128(i as u128)),
                    )?;

                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;

        Ok(rvr_index_cells)
    }
}
