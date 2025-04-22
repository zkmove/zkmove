use crate::chips::execution_chip_v2::step_v2::NUM_OF_VALUE_LIMBS;
use crate::chips::execution_chip_v2::utils::to_field::ToFields;
use halo2_proofs::plonk::{Column, ConstraintSystem, Expression, Instance, VirtualCells};
use halo2_proofs::poly::Rotation;
use move_vm_runtime::witnessing::traced_value::ValueItems;
use types::Field;

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

pub fn public_inputs_to_fields<F: Field>(
    args: &[ValueItems],
    public_inputs: &[usize],
) -> Vec<Vec<F>> {
    // Collect fields of all ValueItems as rows
    let mut rows: Vec<Vec<F>> = Vec::new();
    for &index in public_inputs {
        if index < args.len() {
            let value_items = &args[index];
            for value_item in value_items {
                let fields = value_item.to_fields();
                assert_eq!(
                    fields.len(),
                    NUM_OF_VALUE_LIMBS + 2,
                    "Each ValueItem must produce {} fields (sub_index, header, {} value limbs)",
                    NUM_OF_VALUE_LIMBS + 2,
                    NUM_OF_VALUE_LIMBS
                );
                rows.push(fields);
            }
        }
    }

    // Transpose rows to columns, or return single zero columns if empty
    let mut columns: Vec<Vec<F>> = vec![Vec::new(); NUM_OF_VALUE_LIMBS + 2];
    if rows.is_empty() {
        columns.iter_mut().for_each(|col| col.push(F::zero()));
    } else {
        for row in rows {
            for (i, field) in row.into_iter().enumerate() {
                columns[i].push(field);
            }
        }
    }

    columns
}
