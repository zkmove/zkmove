use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Any, Column, Error, Fixed};
use types::Field;

pub(crate) fn assign_fixed_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    table_columns: Vec<Column<Fixed>>,
    values: &Vec<Vec<F>>,
    table_name: &str,
) -> Result<(), Error> {
    layouter.assign_region(
        || format!("assign fixed table"),
        |mut region| {
            for (column_idx, column) in table_columns.iter().enumerate() {
                region.assign_fixed(
                    || format!("{:?}[{}][0]", table_name, column_idx),
                    *column,
                    0,
                    || Value::known(F::ZERO),
                )?;
                for i in 0..values.len() {
                    region.assign_fixed(
                        || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                        *column,
                        i + 1,
                        || Value::known(values[i][column_idx]),
                    )?;
                }
            }
            Ok(())
        },
    )?;
    Ok(())
}
