// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, TableColumn};

use types::Field;

#[derive(Clone, Copy, Debug)]
pub struct BitwiseLookupTable {
    pub opcode_column: TableColumn,
    pub value_1_column: TableColumn,
    pub value_2_column: TableColumn,
    pub result_column: TableColumn,
}

impl BitwiseLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        BitwiseLookupTable {
            opcode_column: meta.lookup_table_column(),
            value_1_column: meta.lookup_table_column(),
            value_2_column: meta.lookup_table_column(),
            result_column: meta.lookup_table_column(),
        }
    }

    pub fn table_columns(&self) -> Vec<TableColumn> {
        vec![
            self.opcode_column,
            self.value_1_column,
            self.value_2_column,
            self.result_column,
        ]
    }
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // bitwise table
        // only 4 bits bitwised every time. so table size is 16*16
        let mut bitwise_values = Vec::new();
        for op in [Opcode::BitAnd, Opcode::BitOr, Opcode::Xor] {
            for value_1 in 0..16 {
                for value_2 in 0..16 {
                    let field_values = vec![
                        F::from_u128(op.index() as u128),
                        F::from_u128(value_1 as u128),
                        F::from_u128(value_2 as u128),
                        match op {
                            Opcode::BitAnd => F::from_u128((value_1 & value_2) as u128),
                            Opcode::BitOr => F::from_u128((value_1 | value_2) as u128),
                            Opcode::Xor => F::from_u128((value_1 ^ value_2) as u128),
                            _ => unreachable!(),
                        },
                    ];
                    bitwise_values.push(field_values);
                }
            }
        }
        assign_fixed_table(
            layouter,
            self.table_columns().iter().map(|t| t.inner()).collect(),
            &bitwise_values,
            "bitwise_table",
        )
    }
}

impl<F: Field> LookupTable<F> for BitwiseLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.table_columns()
            .into_iter()
            .map(|c| c.inner().into())
            .collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["opcode", "value_1", "value_2", "result"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
