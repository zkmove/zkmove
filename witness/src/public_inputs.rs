use move_vm_runtime::witnessing::traced_value::{ValueItem, ValueItems};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicInputRows {
    rows: BTreeMap<(usize, Vec<usize>), usize>,
}

impl PublicInputRows {
    pub fn new(args: &[ValueItems], pubs_indices: &[usize]) -> Self {
        let rows = public_input_items(args, pubs_indices)
            .into_iter()
            .enumerate()
            .map(|(row, (arg_index, item))| ((arg_index, item.sub_index.clone()), row))
            .collect();

        Self { rows }
    }

    pub fn get(&self, arg_index: usize, sub_index: &[usize]) -> Option<usize> {
        self.rows.get(&(arg_index, sub_index.to_vec())).copied()
    }
}

pub fn public_input_items<'a>(
    args: &'a [ValueItems],
    pubs_indices: &[usize],
) -> Vec<(usize, &'a ValueItem)> {
    pubs_indices
        .iter()
        .filter_map(|&arg_index| args.get(arg_index).map(|items| (arg_index, items)))
        .flat_map(|(arg_index, items)| items.iter().map(move |item| (arg_index, item)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimpleValue;
    use std::collections::BTreeMap;

    fn value_item(sub_index: &[usize], value: u64) -> ValueItem {
        ValueItem {
            sub_index: sub_index.to_vec(),
            header: false,
            value: SimpleValue::U64(value),
        }
    }

    #[test]
    fn public_input_rows_map_second_arg_to_first_row() {
        let args = vec![vec![value_item(&[], 10)], vec![value_item(&[], 20)]];
        let rows = PublicInputRows::new(&args, &[1]);

        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.get(1, &[]), Some(0));
        assert_eq!(rows.get(0, &[]), None);
    }

    #[test]
    fn public_input_rows_follow_pubs_indices_order() {
        let args = vec![
            vec![value_item(&[], 10)],
            vec![value_item(&[], 20)],
            vec![
                value_item(&[], 30),
                value_item(&[1], 31),
                value_item(&[2], 32),
            ],
        ];
        let rows = PublicInputRows::new(&args, &[2, 0]);

        assert_eq!(rows.rows.len(), 4);
        assert_eq!(rows.get(2, &[]), Some(0));
        assert_eq!(rows.get(2, &[1]), Some(1));
        assert_eq!(rows.get(2, &[2]), Some(2));
        assert_eq!(rows.get(0, &[]), Some(3));
        assert_eq!(rows.get(1, &[]), None);
    }

    #[test]
    fn public_input_items_follow_row_order() {
        let args = vec![
            vec![value_item(&[], 10)],
            vec![value_item(&[], 20)],
            vec![value_item(&[], 30), value_item(&[1], 31)],
        ];
        let items = public_input_items(&args, &[2, 0]);

        let ordered_values = items
            .iter()
            .map(|(arg_index, item)| (*arg_index, item.sub_index.clone()))
            .collect::<Vec<_>>();
        assert_eq!(ordered_values, vec![(2, vec![]), (2, vec![1]), (0, vec![])]);
    }

    #[test]
    fn public_input_rows_are_derived_from_public_input_items() {
        let args = vec![
            vec![value_item(&[], 10)],
            vec![value_item(&[], 20)],
            vec![value_item(&[], 30), value_item(&[1], 31)],
        ];
        let pubs_indices = [2, 0];
        let rows = PublicInputRows::new(&args, &pubs_indices);
        let expected = public_input_items(&args, &pubs_indices)
            .into_iter()
            .enumerate()
            .map(|(row, (arg_index, item))| ((arg_index, item.sub_index.clone()), row))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(rows.rows, expected);
    }
}
