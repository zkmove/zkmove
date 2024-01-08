// use crate::chips::execution_chip::lookup_tables::utils::assign_table;
// use crate::chips::execution_chip::opcode::Opcode;
// use halo2_base::halo2_proofs::circuit::Layouter;
// use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::plonk::{Expression, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct BitwiseLookupTable {
    pub opcode_column: TableColumn,
    pub value_1_column: TableColumn,
    pub value_2_column: TableColumn,
    pub result_column: TableColumn,
}
pub const BITWISE_LOOKUP_TABLE_WIDTH: usize = 4;

impl BitwiseLookupTable {
    // pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
    //     BitwiseLookupTable {
    //         opcode_column: meta.lookup_table_column(),
    //         value_1_column: meta.lookup_table_column(),
    //         value_2_column: meta.lookup_table_column(),
    //         result_column: meta.lookup_table_column(),
    //     }
    // }

    // pub fn columns(&self) -> Vec<TableColumn> {
    //     vec![
    //         self.opcode_column,
    //         self.value_1_column,
    //         self.value_2_column,
    //         self.result_column,
    //     ]
    // }

    // pub fn assign_table<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
    //     // bitwise table
    //     // only 4 bits bitwised every time. so table size is 16*16
    //     let mut bitwise_values = Vec::new();
    //     for op in [Opcode::BitAnd, Opcode::BitOr, Opcode::Xor] {
    //         for value_1 in 0..16 {
    //             for value_2 in 0..16 {
    //                 let field_values = vec![
    //                     F::from_u128(op.index() as u128),
    //                     F::from_u128(value_1 as u128),
    //                     F::from_u128(value_2 as u128),
    //                     match op {
    //                         Opcode::BitAnd => F::from_u128((value_1 & value_2) as u128),
    //                         Opcode::BitOr => F::from_u128((value_1 | value_2) as u128),
    //                         Opcode::Xor => F::from_u128((value_1 ^ value_2) as u128),
    //                         _ => unreachable!(),
    //                     },
    //                 ];
    //                 bitwise_values.push(field_values);
    //             }
    //         }
    //     }
    //     assign_table(layouter, self.columns(), &bitwise_values, "bitwise_table")
    // }

    // NOTICE: table height must be consistent with assign_table()
    // pub fn table_height(&self) -> usize {
    //     3 * 16 * 16 + 1
    // }
}

#[derive(Clone, Debug)]
pub struct BitwiseLookup<F: Field> {
    pub opcode: Expression<F>,
    pub value_1: Expression<F>,
    pub value_2: Expression<F>,
    pub result: Expression<F>,
}

impl<F: Field> BitwiseLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.opcode.clone(),
            self.value_1.clone(),
            self.value_2.clone(),
            self.result.clone(),
        ]
    }
}
