// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::constant_table::flatten::Flatten;
use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::chips::execution_chip_v2::step_v2::NUM_OF_VALUE_LIMBS;
use crate::chips::execution_chip_v2::utils::to_field::ToField;
use crate::table::LookupTable;
use crate::witness::static_info::constant::ConstantInfo;
use crate::witness::static_info::StaticInfo;
use aptos_move_witnesses::utils::SubIndexUtils;
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
                let rows: Vec<ConstantTableRow> = c.clone().into();
                rows.iter().map(|row| row.to_fe()).collect::<Vec<_>>()
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
    module_index: usize,
    constant_index: usize,
    value_item: ValueItem,
}

impl ConstantTableRow {
    fn to_fe<F: Field>(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.constant_index as u128),
            F::from_u128(self.value_item.sub_index.into_u128()),
        ]
        .into_iter()
        .chain(self.value_item.value.to_field())
        .chain(vec![F::from(self.value_item.header as u64)])
        .collect()
    }
}
impl From<ConstantInfo> for Vec<ConstantTableRow> {
    fn from(constant: ConstantInfo) -> Vec<ConstantTableRow> {
        let items = constant.value.flatten(vec![0]);
        items
            .iter()
            .map(|item| ConstantTableRow {
                module_index: constant.module_index,
                constant_index: constant.constant_index,
                value_item: item.clone(),
            })
            .collect()
    }
}

pub mod flatten {
    use aptos_move_witnesses::step_state::SubIndex;
    use aptos_move_witnesses::sub_index;
    use aptos_move_witnesses::utils::ValueHeader;
    use aptos_move_witnesses::{SimpleValue, ValueItem};
    use move_core_types::value::MoveValue;

    pub trait Flatten {
        fn flatten(self, sub_index: SubIndex) -> Vec<ValueItem>;
        fn flen(&self) -> usize;
    }

    impl Flatten for MoveValue {
        fn flatten(self, sub_index: SubIndex) -> Vec<ValueItem> {
            let flen = self.flen();
            match self {
                MoveValue::U8(u) => vec![value_item(sub_index, SimpleValue::U8(u))],
                MoveValue::U16(u) => vec![value_item(sub_index, SimpleValue::U16(u))],
                MoveValue::U32(u) => vec![value_item(sub_index, SimpleValue::U32(u))],
                MoveValue::U64(u) => vec![value_item(sub_index, SimpleValue::U64(u))],
                MoveValue::U128(u) => vec![value_item(sub_index, SimpleValue::U128(u))],
                MoveValue::U256(u) => vec![value_item(sub_index, SimpleValue::U256(u))],
                MoveValue::Bool(b) => vec![value_item(sub_index, SimpleValue::Bool(b))],
                MoveValue::Vector(values) => {
                    let len = values.len();
                    let mut items = Vec::new();
                    items.push(header_item(sub_index.clone(), flen, len));

                    for (i, value) in values.into_iter().enumerate() {
                        let value_sub_index = sub_index::concat(sub_index.clone(), vec![i + 1]);
                        let mut flattened_value = value.flatten(value_sub_index);
                        items.append(&mut flattened_value);
                    }
                    items
                }
                _ => unimplemented!(),
            }
        }

        fn flen(&self) -> usize {
            match self {
                MoveValue::U8(_)
                | MoveValue::U16(_)
                | MoveValue::U32(_)
                | MoveValue::U64(_)
                | MoveValue::U128(_)
                | MoveValue::U256(_)
                | MoveValue::Bool(_) => 1,
                MoveValue::Vector(values) => values.iter().fold(0, |sum, v| sum + v.flen()) + 1,
                _ => unimplemented!(),
            }
        }
    }

    fn value_item(sub_index: SubIndex, simple: SimpleValue) -> ValueItem {
        ValueItem {
            sub_index,
            header: false,
            value: simple,
        }
    }
    fn header_item(sub_index: SubIndex, flen: usize, len: usize) -> ValueItem {
        ValueItem {
            sub_index,
            header: true,
            value: ValueHeader::new(flen as u16, len as u16).into(),
        }
    }
}
