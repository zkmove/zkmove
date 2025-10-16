use crate::chips::execution_chip::lookup_table::constant_table::ConstantTableRow;
use crate::chips::execution_chip::lookup_table::function_table::FunctionTableRow;
use crate::chips::execution_chip::utils::to_field::{ToField, ToFields};
use aptos_move_witnesses::static_info::bytecode::BytecodeInfo;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Column, ErrorFront as Error, Fixed};
use types::Field;

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
                    || Value::known(F::ZERO),
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

impl<F: Field> ToFields<F> for FunctionTableRow {
    fn to_fields(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_handle_index as u128),
            F::from_u128(self.def_module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.num_arg as u128),
            if self.entry { F::ONE } else { F::ZERO },
        ]
    }
}

impl<F: Field> ToFields<F> for ConstantTableRow {
    fn to_fields(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.constant_index as u128),
            self.sub_index.to_field(),
        ]
        .into_iter()
        .chain(self.value.to_fields())
        .chain(vec![F::from(self.header as u64)])
        .collect()
    }
}

impl<F: Field> ToFields<F> for BytecodeInfo {
    fn to_fields(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.pc as u128),
            F::from_u128(self.opcode as u128),
            F::from_u128(self.operand0.unwrap_or_default()),
            F::from_u128(self.operand1.unwrap_or_default()),
        ]
    }
}
