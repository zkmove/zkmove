// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed, TableColumn};
use move_binary_format::file_format_common::Opcodes;
use types::Field;

#[derive(Clone, Copy, Debug)]
pub struct BitwiseLookupTable {
    pub opcode_column: Column<Fixed>,
    pub value_1_column: Column<Fixed>,
    pub value_2_column: Column<Fixed>,
    pub result_column: Column<Fixed>,
}

impl BitwiseLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        BitwiseLookupTable {
            opcode_column: meta.fixed_column(),
            value_1_column: meta.fixed_column(),
            value_2_column: meta.fixed_column(),
            result_column: meta.fixed_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![
            self.opcode_column,
            self.value_1_column,
            self.value_2_column,
            self.result_column,
        ]
    }

    pub fn build<F: Field>(&self) -> impl Iterator<Item = [F; 4]> {
        // Helper function to generate bitwise operation values
        fn generate_bitwise_values<F: Field>(
            opcode: Opcodes,
            operation: fn(u64, u64) -> u64,
        ) -> impl Iterator<Item = [F; 4]> {
            (0..16).flat_map(move |lhs| {
                (0..16).map(move |rhs| {
                    [
                        F::from(opcode as u64),
                        F::from(lhs),
                        F::from(rhs),
                        F::from(operation(lhs, rhs)),
                    ]
                })
            })
        }

        // Combine all iterators into one
        generate_bitwise_values(Opcodes::BIT_AND, |lhs, rhs| lhs & rhs)
            .chain(generate_bitwise_values(Opcodes::BIT_OR, |lhs, rhs| {
                lhs | rhs
            }))
            .chain(generate_bitwise_values(Opcodes::XOR, |lhs, rhs| lhs ^ rhs))
    }

    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bitwise_values: Vec<Vec<F>> = self.build().map(|row| row.to_vec()).collect();
        assign_fixed_table(layouter, self.columns(), &bitwise_values, "bitwise_table")
    }
}

impl<F: Field> LookupTable<F> for BitwiseLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.columns().into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["opcode", "value_1", "value_2", "result"]
            .into_iter()
            .map(ToString::to_string)
            .collect()
    }
}
