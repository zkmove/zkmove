// Copyright (c) zkMove Authors

pub mod sub_index;
pub mod value_header;
pub mod word;

pub mod utils {
    use crate::value::sub_index::SubIndex;
    use crate::value::value_header::ValueHeader;
    use crate::value::word::Word;
    use crate::{SimpleValue, ValueItem};
    use field_exts::Field;
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

    pub trait ToFields<F: Field> {
        fn to_fields(&self) -> Vec<F>;
    }
    pub trait ToField<F: Field> {
        fn to_field(&self) -> F;
    }

    impl<F: Field> ToField<F> for bool {
        fn to_field(&self) -> F {
            if *self {
                F::ONE
            } else {
                F::ZERO
            }
        }
    }

    impl<F: Field> ToFields<F> for ValueItem {
        fn to_fields(&self) -> Vec<F> {
            vec![
                SubIndex::new(self.sub_index.clone()).to_field(),
                self.header.to_field(),
            ]
            .into_iter()
            .chain(Word::from(&self.value).to_fields())
            .collect()
        }
    }
}
