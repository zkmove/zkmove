use halo2_base::halo2_proofs::circuit::{Layouter, Value};
use halo2_base::halo2_proofs::plonk::{Error, TableColumn};
use types::Field;

#[allow(clippy::manual_try_fold)]
pub(crate) fn assign_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    table_columns: Vec<TableColumn>,
    values: &Vec<Vec<F>>,
    table_name: &str,
) -> Result<(), Error> {
    for (column_idx, column) in table_columns.into_iter().enumerate() {
        layouter.assign_table(
            || format!("{:?}[{}]", table_name, column_idx),
            |mut table_column| {
                table_column.assign_cell(
                    || format!("{:?}[{}][0]", table_name, column_idx),
                    column,
                    0,
                    || Value::known(F::ZERO),
                )?;
                (0..values.len())
                    .map(|i| {
                        table_column.assign_cell(
                            || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                            column,
                            i + 1,
                            || Value::known(values[i][column_idx]),
                        )
                    })
                    .fold(Ok(()), |acc, res| acc.and(res))
            },
        )?;
    }
    Ok(())
}
