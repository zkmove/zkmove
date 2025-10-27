// Copyright (c) zkMove Authors

use crate::execution_circuit::step::NUM_OF_VALUE_LIMBS;
use crate::lookup_table::utils::assign_fixed_table;
use crate::lookup_table::LookupTable;
use field_exts::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, ErrorFront as Error, Fixed};
use witness::static_info::StaticInfo;
use witness::value::sub_index::SubIndex;
use witness::value::utils::Flatten;
use witness::value::utils::ToFields;
use witness::value::word::Word;

#[derive(Clone, Copy, Debug)]
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
            value: [meta.fixed_column(), meta.fixed_column()],
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
    pub fn build<F: Field>(&self, static_info: &StaticInfo) -> Vec<Vec<F>> {
        static_info
            .constant_info
            .iter()
            .flat_map(|c| {
                let rows: Vec<_> = c
                    .value
                    .clone()
                    .flatten()
                    .iter()
                    .map(|item| ConstantTableRow {
                        module_index: c.module_index,
                        constant_index: c.constant_index,
                        sub_index: SubIndex::new(item.sub_index.clone()),
                        value: item.value.clone().into(),
                        header: item.header,
                    })
                    .collect::<Vec<_>>();
                rows.iter().map(|row| row.to_fields()).collect::<Vec<_>>()
            })
            .collect()
    }
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        assign_fixed_table(
            layouter,
            self.columns(),
            &self.build(static_info),
            "constant_table",
        )
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
    pub module_index: u32,
    pub constant_index: u16,
    pub sub_index: SubIndex,
    pub value: Word,
    pub header: bool,
}
