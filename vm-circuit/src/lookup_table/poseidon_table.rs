use crate::lookup_table::LookupTable;
use field_exts::Field;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Any, Column, ConstraintSystem, ErrorFront as Error, Fixed};
use itertools::Itertools;

/// The Poseidon hash table shared between Hash Circuit, Mpt Circuit and
/// Bytecode Circuit
/// the 5 cols represent [index(final hash of inputs), input0, input1, control,
/// heading mark]
#[derive(Clone, Copy, Debug)]
pub struct PoseidonTable {
    /// Is Enabled
    pub q_enable: Column<Fixed>,
    /// Hash id
    pub hash_id: Column<Advice>,
    /// input0
    pub input0: Column<Advice>,
    /// input1
    pub input1: Column<Advice>,
    /// control
    pub control: Column<Advice>,
    /// domain spec
    pub domain_spec: Column<Advice>,
    /// heading_mark
    pub heading_mark: Column<Advice>,
}

impl<F: Field> crate::lookup_table::LookupTable<F> for PoseidonTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.hash_id.into(),
            self.input0.into(),
            self.input1.into(),
            self.control.into(),
            self.domain_spec.into(),
            self.heading_mark.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("hash_id"),
            String::from("input0"),
            String::from("input1"),
            String::from("control"),
            String::from("domain spec"),
            String::from("heading_mark"),
        ]
    }
}

impl PoseidonTable {
    /// the permutation width of current poseidon table
    pub(crate) const WIDTH: usize = 3;

    /// the input width of current poseidon table
    pub(crate) const INPUT_WIDTH: usize = Self::WIDTH - 1;

    /// Construct a new PoseidonTable
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            hash_id: meta.advice_column(),
            input0: meta.advice_column(),
            input1: meta.advice_column(),
            control: meta.advice_column(),
            domain_spec: meta.advice_column(),
            heading_mark: meta.advice_column(),
        }
    }

    /// Load mpt hashes (without the poseidon circuit) for testing purposes.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        hashes: &[[Value<F>; 6]],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "poseidon table",
            |mut region| {
                self.assign(&mut region, 0, [Value::known(F::zero()); 6])?;
                for (offset, row) in hashes.iter().enumerate() {
                    self.assign(&mut region, offset + 1, *row)?;
                }
                Ok(())
            },
        )
    }

    // /// Provide this function for the case that we want to consume a poseidon
    // /// table but without running the full poseidon circuit
    // pub fn dev_load<'a, F: Field>(
    //     &self,
    //     layouter: &mut impl Layouter<F>,
    //     inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
    // ) -> Result<(), Error> {
    //     use crate::bytecode_circuit::bytecode_unroller::{
    //         unroll_to_hash_input_default, HASHBLOCK_BYTES_IN_FIELD,
    //     };
    //     use eth_types::state_db::CodeDB;
    //     use hash_circuit::hash::HASHABLE_DOMAIN_SPEC;
    //
    //     layouter.assign_region(
    //         || "poseidon codehash table",
    //         |mut region| {
    //             let mut offset = 0;
    //             let poseidon_table_columns =
    //                 <PoseidonTable as LookupTable<F>>::advice_columns(self);
    //
    //             region.assign_fixed(
    //                 || "poseidon table all-zero row",
    //                 self.q_enable,
    //                 offset,
    //                 || Value::known(F::zero()),
    //             )?;
    //             for column in poseidon_table_columns.iter().copied() {
    //                 region.assign_advice(
    //                     || "poseidon table all-zero row",
    //                     column,
    //                     offset,
    //                     || Value::known(F::zero()),
    //                 )?;
    //             }
    //             offset += 1;
    //             // let nil_hash =
    //             //     Value::known(CodeDB::empty_code_hash().to_word().to_scalar().unwrap());
    //             // region.assign_fixed(
    //             //     || "poseidon table nil input row",
    //             //     self.q_enable,
    //             //     offset,
    //             //     || Value::known(F::one()),
    //             // )?;
    //             // for (column, value) in poseidon_table_columns
    //             //     .iter()
    //             //     .copied()
    //             //     .zip(once(nil_hash).chain(repeat(Value::known(F::zero()))))
    //             // {
    //             //     region.assign_advice(
    //             //         || "poseidon table nil input row",
    //             //         column,
    //             //         offset,
    //             //         || value,
    //             //     )?;
    //             // }
    //             offset += 1;
    //
    //             for input in inputs.clone() {
    //                 let mut control_len = input.len();
    //                 let mut first_row = true;
    //                 let ref_hash = Value::known(
    //                     CodeDB::hash(input.as_slice())
    //                         .to_word()
    //                         .to_scalar()
    //                         .unwrap(),
    //                 );
    //                 for row in unroll_to_hash_input_default::<F>(input.iter().copied()) {
    //                     assert_ne!(
    //                         control_len,
    //                         0,
    //                         "must have enough len left (original size {})",
    //                         input.len()
    //                     );
    //                     let block_size = HASHBLOCK_BYTES_IN_FIELD * row.len();
    //                     let control_len_as_flag =
    //                         F::from_u128(HASHABLE_DOMAIN_SPEC * control_len as u128);
    //
    //                     region.assign_fixed(
    //                         || format!("poseidon table row {offset}"),
    //                         self.q_enable,
    //                         offset,
    //                         || Value::known(F::one()),
    //                     )?;
    //                     for (column, value) in poseidon_table_columns.iter().zip_eq(
    //                         once(ref_hash)
    //                             .chain(row.map(Value::known))
    //                             .chain(once(Value::known(control_len_as_flag)))
    //                             .chain(once(Value::known(F::zero()))) // always use domain 0 in codehash
    //                             .chain(once(Value::known(if first_row {
    //                                 F::one()
    //                             } else {
    //                                 F::zero()
    //                             }))),
    //                     ) {
    //                         region.assign_advice(
    //                             || format!("poseidon table row {offset}"),
    //                             *column,
    //                             offset,
    //                             || value,
    //                         )?;
    //                     }
    //                     first_row = false;
    //                     offset += 1;
    //                     control_len = if control_len > block_size {
    //                         control_len - block_size
    //                     } else {
    //                         0
    //                     };
    //                 }
    //                 assert_eq!(
    //                     control_len,
    //                     0,
    //                     "should have exhaust all bytes (original size {})",
    //                     input.len()
    //                 );
    //             }
    //             Ok(())
    //         },
    //     )
    // }

    fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: [Value<F>; 6],
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "assign poseidon table row value",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        let poseidon_table_columns = <PoseidonTable as LookupTable<F>>::advice_columns(self);
        for (column, value) in poseidon_table_columns.iter().zip_eq(row) {
            region.assign_advice(
                || "assign poseidon table row value",
                *column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }
}
