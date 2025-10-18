use crate::execution_circuit::step::NUM_OF_VALUE_LIMBS;
use crate::execution_circuit::utils::to_field::ToFields;
use halo2_proofs::plonk::{Column, ConstraintSystem, Expression, Instance, VirtualCells};
use halo2_proofs::poly::Rotation;
use move_vm_runtime::witnessing::traced_value::ValueItems;
use types::Field;

pub const NUM_INSTANCE_COLUMNS: usize = NUM_OF_VALUE_LIMBS + 2;

#[derive(Clone)]
pub struct InstanceTable {
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
        value.map(|c| meta.enable_equality(c));
        Self {
            sub_index,
            header,
            value,
        }
    }
    pub fn columns(&self) -> Vec<Column<Instance>> {
        vec![self.sub_index, self.header]
            .into_iter()
            .chain(self.value)
            .collect()
    }
    pub fn exprs<F: Field>(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
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
                    let fields = value_item.to_fields();
                    assert_eq!(
                        fields.len(),
                        NUM_INSTANCE_COLUMNS,
                        "Each ValueItem must produce {} fields",
                        NUM_INSTANCE_COLUMNS
                    );
                    rows.push(fields);
                }
            }
        }

        let mut columns: Vec<Vec<F>> = vec![Vec::new(); NUM_INSTANCE_COLUMNS];
        if rows.is_empty() {
            columns.iter_mut().for_each(|col| col.push(F::zero()));
        } else {
            for row in rows {
                for (i, field) in row.into_iter().enumerate() {
                    columns[i].push(field);
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
            for field in column {
                let field_bytes: [u8; 32] = field.to_repr().as_ref().try_into().unwrap();
                bytes.extend_from_slice(&field_bytes);
            }
        }
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let field_byte_len = F::Repr::default().as_ref().len();
        let num_columns = NUM_INSTANCE_COLUMNS;
        assert_eq!(bytes.len() % field_byte_len, 0, "Byte length not aligned");
        let num_fields = bytes.len() / field_byte_len;
        assert_eq!(num_fields % num_columns, 0, "Field count not aligned");
        let num_rows = num_fields / num_columns;

        let mut columns = vec![Vec::with_capacity(num_rows); num_columns];
        for col in 0..num_columns {
            for row in 0..num_rows {
                let i = col * num_rows + row;
                let start = i * field_byte_len;
                let end = start + field_byte_len;
                let mut repr = F::Repr::default();
                repr.as_mut().copy_from_slice(&bytes[start..end]);
                let field = F::from_repr(repr).unwrap();
                columns[col].push(field);
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
