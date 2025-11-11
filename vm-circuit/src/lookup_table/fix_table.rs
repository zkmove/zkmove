use crate::lookup_table::FixedTableTag;
use crate::lookup_table::LookupTable;
use field_exts::Field;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, ErrorFront as Error, Fixed};
use itertools::Itertools;

#[derive(Clone, Copy, Debug)]
pub struct FixedTable {
    cols: [Column<Fixed>; 4],
}

impl FixedTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        Self { cols: fixed_table }
    }

    /// Load fixed table
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.cols.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for FixedTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.cols.into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["tag", "fix(0)", "fix(1)", "fix(2)"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
