// Copyright (c) zkMove Authors

use crate::static_info::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_binary_format::CompiledModule;
use move_core_types::value::MoveValue;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ConstantInfo {
    pub module_index: usize,
    pub constant_index: usize,
    pub value: MoveValue,
}

pub(crate) fn parse_constant(
    module_id_mapping: &ModuleIdMapping,
    deps: &[CompiledModule],
) -> Vec<ConstantInfo> {
    deps.iter()
        .flat_map(|module| {
            module
                .constant_pool()
                .iter()
                .enumerate()
                .map(|(idx, constant)| {
                    #[allow(clippy::expect_fun_call)]
                    let value = constant.deserialize_constant().expect(&format!(
                        "deserialize_constant {} at module {:?} should not fail",
                        idx,
                        module.self_id()
                    ));
                    ConstantInfo {
                        module_index: module_id_mapping.get_module_index(&module.self_id()),
                        constant_index: idx,
                        value,
                    }
                })
        })
        .collect()
}

pub mod flatten {
    use crate::types::value_header::ValueHeader;
    use crate::{SimpleValue, ValueItem};
    use move_core_types::value::MoveValue;

    pub trait Flatten {
        fn flatten(self) -> Vec<ValueItem>;
        fn flatten_with(self, sub_index: Vec<usize>) -> Vec<ValueItem>;

        fn flen(&self) -> usize;
    }

    impl Flatten for MoveValue {
        fn flatten(self) -> Vec<ValueItem> {
            self.flatten_with(vec![0])
        }
        fn flatten_with(self, sub_index: Vec<usize>) -> Vec<ValueItem> {
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
                        let value_sub_index = concat(sub_index.clone(), vec![i + 1]);
                        let mut flattened_value = value.flatten_with(value_sub_index);
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

    fn value_item(sub_index: Vec<usize>, simple: SimpleValue) -> ValueItem {
        ValueItem {
            sub_index,
            header: false,
            value: simple,
        }
    }
    fn header_item(sub_index: Vec<usize>, flen: usize, len: usize) -> ValueItem {
        ValueItem {
            sub_index,
            header: true,
            value: ValueHeader::new(flen, len).into(),
        }
    }
    fn concat(mut index1: Vec<usize>, mut index2: Vec<usize>) -> Vec<usize> {
        while let Some(0) = index1.last() {
            index1.pop();
        }

        index1.append(&mut index2);
        index1
    }
}
