use crate::lookup_table::constant_table::ConstantTableRow;
use crate::lookup_table::function_table::FunctionTableRow;
use field_exts::util::Scalar;
use field_exts::Field;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Column, ErrorFront as Error, Fixed};
use value_type::to_scalars::ToScalars;

pub(crate) fn assign_fixed_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    table_columns: Vec<Column<Fixed>>,
    values: &[Vec<F>],
    table_name: &str,
) -> Result<(), Error> {
    layouter.assign_region(
        || "assign fixed table".to_string(),
        |mut region| {
            for (column_idx, column) in table_columns.iter().enumerate() {
                region.assign_fixed(
                    || format!("{:?}[{}][0]", table_name, column_idx),
                    *column,
                    0,
                    || Value::known(F::zero()),
                )?;
                for (i, item) in values.iter().enumerate() {
                    region.assign_fixed(
                        || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                        *column,
                        i + 1,
                        || Value::known(item[column_idx]),
                    )?;
                }
            }
            Ok(())
        },
    )
}

impl<F: Field> ToScalars<F> for FunctionTableRow {
    fn to_scalars(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_handle_index as u128),
            F::from_u128(self.def_module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.num_arg as u128),
            if self.entry { F::one() } else { F::zero() },
        ]
    }
}

impl<F: Field> ToScalars<F> for ConstantTableRow {
    fn to_scalars(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.constant_index as u128),
            self.sub_index.scalar(),
        ]
        .into_iter()
        .chain(self.value.to_scalars())
        .chain(vec![F::from(self.header as u64)])
        .collect()
    }
}
