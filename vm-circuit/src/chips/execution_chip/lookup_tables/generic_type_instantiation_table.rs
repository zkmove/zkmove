use crate::witness::generic_type_instantiations::GenericTypeInstantiationTableItem;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::Value as CircuitValue;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression};

#[derive(Clone, Debug)]
pub struct GenericTypeInstantiationTable {
    frame_index_plus_one: Column<Advice>,
    call_id: Column<Advice>,
    call_module: Column<Advice>,
    call_function: Column<Advice>,
    call_pc: Column<Advice>,

    ty_arg_pos: Column<Advice>,
    ty_arg_module: Column<Advice>,
    ty_arg_name: Column<Advice>,
}

impl GenericTypeInstantiationTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            call_id: meta.advice_column(),
            call_module: meta.advice_column(),
            call_function: meta.advice_column(),
            call_pc: meta.advice_column(),
            frame_index_plus_one: meta.advice_column(),
            ty_arg_pos: meta.advice_column(),
            ty_arg_module: meta.advice_column(),
            ty_arg_name: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.call_id,
            self.call_module,
            self.call_function,
            self.call_pc,
            self.frame_index_plus_one,
            self.ty_arg_pos,
            self.ty_arg_module,
            self.ty_arg_name,
        ]
    }

    pub fn assign_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        items: Vec<GenericTypeInstantiationTableItem>,
    ) -> Result<(), Error> {
        let items: Vec<_> = items
            .into_iter()
            .map(|item| {
                vec![
                    F::from_u128(item.call_id),
                    F::from_u128(item.call_module as u128),
                    F::from_u128(item.call_function as u128),
                    F::from_u128(item.call_pc as u128),
                    F::from_u128(item.frame_index_plus_one as u128),
                    F::from_u128(item.ty_arg_pos),
                    F::from_u128(item.ty_arg_module as u128),
                    F::from_u128(item.ty_arg_name as u128),
                ]
            })
            .collect();

        for (column_index, column) in self.columns().into_iter().enumerate() {
            layouter.assign_region(
                || format!("generic_type_instantiation_table[{}]", column_index),
                |mut region| {
                    region.assign_advice(
                        || format!("generic_type_instantiation_table[{}][0]", column_index),
                        column,
                        0,
                        || CircuitValue::known(F::zero()),
                    )?;
                    for (idx, data) in items.iter().enumerate() {
                        region.assign_advice(
                            || {
                                format!(
                                    "generic_type_instantiation_table[{}][{}]",
                                    column_index,
                                    idx + 1
                                )
                            },
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

pub struct GenericTypeInstantiationLookup<F: FieldExt> {
    pub call_id: Expression<F>,
    pub call_module: Expression<F>,
    pub call_function: Expression<F>,
    pub call_pc: Expression<F>,

    pub frame_index_plus_one: Expression<F>,
    pub ty_arg_pos: Expression<F>,
    pub ty_arg_module: Expression<F>,
    pub ty_arg_name: Expression<F>,
}

impl<F: FieldExt> GenericTypeInstantiationLookup<F> {
    pub fn expressions(&self) -> Vec<Expression<F>> {
        vec![
            self.call_id.clone(),
            self.call_module.clone(),
            self.call_function.clone(),
            self.call_pc.clone(),
            self.frame_index_plus_one.clone(),
            self.ty_arg_pos.clone(),
            self.ty_arg_module.clone(),
            self.ty_arg_name.clone(),
        ]
    }
}
