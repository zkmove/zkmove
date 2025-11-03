use crate::execution_circuit::step::NUM_OF_VALUE_LIMBS;
use field_exts::Field;
use halo2_proofs::plonk::{Column, ConstraintSystem, Instance};
use move_vm_runtime::witnessing::traced_value::ValueItems;
use value_type::to_scalars::ToScalars;

pub const NUM_INSTANCE_COLUMNS: usize = NUM_OF_VALUE_LIMBS + 2;

#[derive(Clone)]
pub(crate) struct InstanceTable {
    pub sub_index: Column<Instance>,
    pub header: Column<Instance>,
    pub value: [Column<Instance>; NUM_OF_VALUE_LIMBS],
}

impl InstanceTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let sub_index = meta.instance_column();
        let header = meta.instance_column();
        let value = [(); NUM_OF_VALUE_LIMBS].map(|_| meta.instance_column());
        meta.enable_equality(sub_index);
        meta.enable_equality(header);
        let _ = value.map(|c| meta.enable_equality(c));
        Self {
            sub_index,
            header,
            value,
        }
    }
}

#[derive(Clone)]
pub struct PublicInputs<F: Field>(Vec<Vec<F>>);

impl<F: Field> PublicInputs<F> {
    pub fn new(args: &[ValueItems], pubs_indices: &[usize]) -> Self {
        let mut rows: Vec<Vec<F>> = Vec::new();
        for &index in pubs_indices {
            if index < args.len() {
                let value_items = &args[index];
                for value_item in value_items {
                    let scalars = value_item.to_scalars();
                    assert_eq!(
                        scalars.len(),
                        NUM_INSTANCE_COLUMNS,
                        "Each ValueItem must produce {} scalars",
                        NUM_INSTANCE_COLUMNS
                    );
                    rows.push(scalars);
                }
            }
        }

        let mut columns: Vec<Vec<F>> = vec![Vec::new(); NUM_INSTANCE_COLUMNS];
        if rows.is_empty() {
            columns.iter_mut().for_each(|col| col.push(F::zero()));
        } else {
            for row in rows {
                for (i, scalar) in row.into_iter().enumerate() {
                    columns[i].push(scalar);
                }
            }
        }

        PublicInputs(columns)
    }
    pub fn as_vec(&self) -> Vec<Vec<F>> {
        self.0.clone()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for column in &self.0 {
            for scalar in column {
                let scalar_bytes: [u8; 32] = scalar.to_repr().as_ref().try_into().unwrap();
                bytes.extend_from_slice(&scalar_bytes);
            }
        }
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let scalar_byte_len = F::Repr::default().as_ref().len();
        let num_columns = NUM_INSTANCE_COLUMNS;
        assert_eq!(bytes.len() % scalar_byte_len, 0, "Byte length not aligned");
        let num_scalars = bytes.len() / scalar_byte_len;
        assert_eq!(num_scalars % num_columns, 0, "Field count not aligned");
        let num_rows = num_scalars / num_columns;

        let mut columns = vec![Vec::with_capacity(num_rows); num_columns];
        for col in 0..num_columns {
            for row in 0..num_rows {
                let i = col * num_rows + row;
                let start = i * scalar_byte_len;
                let end = start + scalar_byte_len;
                let mut repr = F::Repr::default();
                repr.as_mut().copy_from_slice(&bytes[start..end]);
                let scalar = F::from_repr(repr).unwrap();
                columns[col].push(scalar);
            }
        }
        PublicInputs(columns)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::rngs::OsRng;

    #[test]
    fn test_to_bytes_and_from_bytes() {
        let num_columns = NUM_INSTANCE_COLUMNS;
        let num_rows = 3;
        let mut columns = vec![Vec::with_capacity(num_rows); num_columns];
        for col in &mut columns {
            for _ in 0..num_rows {
                col.push(Fr::random(OsRng));
            }
        }
        let public_inputs = PublicInputs::<Fr>(columns);

        // Serialize
        let bytes = public_inputs.to_bytes();
        // Deserialize
        let restored = PublicInputs::<Fr>::from_bytes(&bytes);

        // Check that the content is consistent
        assert_eq!(public_inputs.0, restored.0);
    }
}
