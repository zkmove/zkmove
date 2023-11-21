use crate::witness::input_type_elements::{InputTypeElement, InputTypeElementTableData};
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression};
use types::Field;

#[derive(Clone, Debug)]
pub struct InputTypeElementTable {
    ty_arg_pos: Column<Advice>,
    ty_arg_module: Column<Advice>,
    ty_arg_name: Column<Advice>,
}

impl InputTypeElementTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            ty_arg_pos: meta.advice_column(),
            ty_arg_module: meta.advice_column(),
            ty_arg_name: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        vec![self.ty_arg_pos, self.ty_arg_module, self.ty_arg_name]
    }

    pub fn table_height(&self, input_type_elements: &InputTypeElementTableData) -> usize {
        input_type_elements.0.len() + 1
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        items: Vec<InputTypeElement>,
    ) -> Result<(), Error> {
        let items: Vec<_> = items
            .into_iter()
            .map(|item| {
                vec![
                    F::from_u128(item.ty_arg_pos),
                    F::from_u128(item.ty_arg_module as u128),
                    F::from_u128(item.ty_arg_name as u128),
                ]
            })
            .collect();

        for (column_index, column) in self.columns().into_iter().enumerate() {
            layouter.assign_region(
                || format!("input_type_element_table[{}]", column_index),
                |mut region| {
                    region.assign_advice(
                        || format!("input_type_element_table[{}][0]", column_index),
                        column,
                        0,
                        || CircuitValue::known(F::ZERO),
                    )?;
                    for (idx, data) in items.iter().enumerate() {
                        region.assign_advice(
                            || format!("input_type_element_table[{}][{}]", column_index, idx + 1),
                            column,
                            idx + 1,
                            || match data.get(column_index) {
                                Some(d) => CircuitValue::known(*d),
                                None => CircuitValue::unknown(),
                            },
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct InputTypeElementLookup<F: Field> {
    pub ty_arg_pos: Expression<F>,
    pub ty_arg_module: Expression<F>,
    pub ty_arg_name: Expression<F>,
}

impl<F: Field> InputTypeElementLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.ty_arg_pos.clone(),
            self.ty_arg_module.clone(),
            self.ty_arg_name.clone(),
        ]
    }
}
