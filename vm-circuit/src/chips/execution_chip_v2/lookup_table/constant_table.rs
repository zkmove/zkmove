// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::chips::execution_chip_v2::lookup_table::utils::ToFields;
use crate::chips::execution_chip_v2::step_v2::NUM_OF_VALUE_LIMBS;
use crate::table::LookupTable;
use aptos_move_witnesses::static_info::constant::flatten::Flatten;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::ValueItem;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed};
use types::Field;

#[derive(Clone, Debug)]
pub struct ConstantLookupTable {
    pub module_index: Column<Fixed>,
    pub constant_index: Column<Fixed>,
    pub sub_index: Column<Fixed>,
    pub value: [Column<Fixed>; NUM_OF_VALUE_LIMBS],
    pub header: Column<Fixed>,
}

impl ConstantLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        ConstantLookupTable {
            module_index: meta.fixed_column(),
            constant_index: meta.fixed_column(),
            sub_index: meta.fixed_column(),
            value: [meta.fixed_column(); NUM_OF_VALUE_LIMBS],
            header: meta.fixed_column(),
        }
    }
    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![self.module_index, self.constant_index, self.sub_index]
            .into_iter()
            .chain(self.value)
            .chain(vec![self.header])
            .collect()
    }
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        let field_elements: Vec<Vec<F>> = static_info
            .constant_info
            .iter()
            .flat_map(|c| {
                let rows: Vec<_> = c
                    .value
                    .clone()
                    .flatten(vec![0])
                    .iter()
                    .map(|item| ConstantTableRow {
                        module_index: c.module_index,
                        constant_index: c.constant_index,
                        value_item: item.clone(),
                    })
                    .collect::<Vec<_>>();
                rows.iter().map(|row| row.to_fields()).collect::<Vec<_>>()
            })
            .collect();
        assign_fixed_table(layouter, self.columns(), &field_elements, "constant_table")
    }
}

impl<F: Field> LookupTable<F> for ConstantLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.columns().into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        let mut annotations = vec![
            "module_index".to_string(),
            "constant_index".to_string(),
            "sub_index".to_string(),
        ];
        for i in 0..NUM_OF_VALUE_LIMBS {
            annotations.push(format!("value_limb{:?}", i));
        }
        annotations.push("header".to_string());
        annotations
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ConstantTableRow {
    pub module_index: usize,
    pub constant_index: usize,
    pub value_item: ValueItem,
}
