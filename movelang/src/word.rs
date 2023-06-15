// Copyright (c) zkMove Authors

use crate::value::{
    AddressPath, Container, GlobalRef, IndexedLocation, IndexedRef, LocalRef, LocatedValue,
    Location, PrimitiveValue, Reference, Value, ValueLocation, DEPTH_OF_LOCATION_PATH, U128,
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use std::convert::{From, TryFrom, TryInto};
use std::marker::PhantomData;

pub const LEN_OF_REFERENCE_VALUE: usize = 4; // header + DEPTH_OF_LOCATION_PATH + addr_ext
pub const LEN_OF_SIMPLE_VALUE: usize = 2;

/// To efficiently represent a complex value in the circuit, we defined 'word', a uniform
/// flattened value representation, to flatten the complex value into simple values.
#[derive(Clone, Debug)]
pub struct Word<F: FieldExt>(pub Vec<(Vec<u128>, PrimitiveValue<F>)>);

impl<F: FieldExt> From<&Value<F>> for Word<F> {
    fn from(value: &Value<F>) -> Self {
        match value {
            Value::Invalid => Word(vec![]), // TODO: Issue #52
            Value::U8(_) | Value::U64(_) | Value::U128(_) | Value::Bool(_) | Value::Address(_) => {
                let simple = PrimitiveValue::try_from(value).expect("should not fail");
                SimpleValueWord::from(simple).into()
            }
            Value::Container(c) => ContainerValueWord::from(c).into(),
            Value::GlobalRef(_) | Value::IndexedRef(_) | Value::LocalRef(_) => {
                let reference = Reference::try_from(value).expect("should not fail");
                ReferenceValueWord::from(reference).into()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleValueWord<F: FieldExt>(pub [(Vec<u128>, PrimitiveValue<F>); LEN_OF_SIMPLE_VALUE]);

impl<F: FieldExt> From<PrimitiveValue<F>> for SimpleValueWord<F> {
    fn from(value: PrimitiveValue<F>) -> SimpleValueWord<F> {
        SimpleValueWord([
            (vec![0u128], ValueHeader::default_for_simple().into()),
            (vec![1u128], value),
        ])
    }
}

impl<F: FieldExt> From<SimpleValueWord<F>> for Word<F> {
    fn from(word: SimpleValueWord<F>) -> Word<F> {
        Word(word.0.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct ReferenceValueWord<F: FieldExt>(
    pub [(Vec<u128>, PrimitiveValue<F>); LEN_OF_REFERENCE_VALUE],
);

impl<F: FieldExt> ReferenceValueWord<F> {
    fn fold(word: Vec<(Vec<u128>, PrimitiveValue<F>)>) -> Self {
        let mut value: u128 = 0;
        for (i, (_, val)) in word.iter().skip(DEPTH_OF_LOCATION_PATH + 1).enumerate() {
            // fold addr_ext into one cell
            let x = val
                .value()
                .expect("value should not be None.")
                .get_lower_128();
            value += x << (16 * i);
        }

        let mut new_ref_value = word
            .into_iter()
            .take(LEN_OF_REFERENCE_VALUE)
            .collect::<Vec<_>>();

        let (address_path, _) = new_ref_value.pop().expect("value should not be None.");
        new_ref_value.push((address_path, PrimitiveValue::u128(value)));
        let new_word: [(Vec<u128>, PrimitiveValue<F>); LEN_OF_REFERENCE_VALUE] = new_ref_value
            .try_into()
            .unwrap_or_else(|v: Vec<(Vec<u128>, PrimitiveValue<F>)>| {
                panic!(
                    "Expected a Vec of length {} but it was {}",
                    LEN_OF_REFERENCE_VALUE,
                    v.len()
                )
            });
        ReferenceValueWord(new_word)
    }
}

impl<F: FieldExt> From<Reference<F>> for ReferenceValueWord<F> {
    fn from(value: Reference<F>) -> ReferenceValueWord<F> {
        let ref_paths = match value {
            Reference::GlobalRef(GlobalRef { loc, .. }) => {
                // NOTICE: here, we fillup address_path for reference, as reference needs fillup-ed values.
                Location::ValueLocation(ValueLocation::Global(loc))
                    .to_address_path()
                    .fill_up()
                    .into_inner()
            }
            Reference::LocalRef(LocalRef { loc, .. }) => {
                // NOTICE: here, we fillup address_path for reference, as reference needs fillup-ed values.
                Location::ValueLocation(ValueLocation::<F>::Local(loc))
                    .to_address_path()
                    .fill_up()
                    .into_inner()
            }
            Reference::IndexedRef(IndexedRef {
                sub_indexes,
                container_ref,
            }) => {
                // Position 0 is occupied by the container header, so the index needs to be increased by 1.
                let sub_indexes = sub_indexes.iter().map(|idx| idx + 1).collect();
                // NOTICE: here, we fillup address_path for reference, as reference needs fillup-ed values.
                Location::IndexedLocation(IndexedLocation {
                    sub_indexes,
                    value_loc: container_ref.location(),
                })
                .to_address_path()
                .fill_up()
                .into_inner()
            }
        };

        let mut simples = ref_paths
            .into_iter()
            .map(|v| PrimitiveValue::U128(U128(F::from_u128(v))))
            .collect::<Vec<_>>();

        simples.insert(0, ValueHeader::default_for_ref_val().into());
        let word = simples
            .into_iter()
            .enumerate()
            .map(|(i, v)| (vec![i as u128], v))
            .collect::<Vec<_>>();
        ReferenceValueWord::fold(word)
    }
}

impl<F: FieldExt> From<ReferenceValueWord<F>> for Word<F> {
    fn from(word: ReferenceValueWord<F>) -> Word<F> {
        Word(word.0.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct ContainerValueWord<F: FieldExt>(pub Vec<(Vec<u128>, PrimitiveValue<F>)>);

impl<F: FieldExt> From<&Container<F>> for ContainerValueWord<F> {
    fn from(container: &Container<F>) -> ContainerValueWord<F> {
        let mut simples = Vec::new();
        for (idx, val) in container.0.borrow().iter().enumerate() {
            let mut sub_values = Word::from(val).0;
            sub_values.iter_mut().for_each(|(v, _)| {
                // prepend value idx to the sub-struct
                // to leave a place for the header, the index is increased by 1
                v.insert(0, (idx + 1) as u128);
            });
            simples.append(&mut sub_values);
        }
        // add a header element to record the length of the container,
        // and the length of the flattened value,
        // the flattened length includes the header itself.
        let header = ValueHeader::new(simples.len() + 1, container.len());
        simples.insert(0, (vec![0u128], header.into()));
        ContainerValueWord(simples)
    }
}

impl<F: FieldExt> From<ContainerValueWord<F>> for Word<F> {
    fn from(word: ContainerValueWord<F>) -> Word<F> {
        Word(word.0)
    }
}

#[derive(Clone, Debug)]
pub struct LocatedWord<F: FieldExt>(pub Vec<(AddressPath<F>, PrimitiveValue<F>)>);

impl<'v, F: FieldExt> From<LocatedValue<'v, ValueLocation<F>, Value<F>>> for LocatedWord<F> {
    fn from(located_value: LocatedValue<'v, ValueLocation<F>, Value<F>>) -> LocatedWord<F> {
        let v_loc = Location::ValueLocation(located_value.0)
            .to_address_path()
            .into_inner();
        let mut values = Word::from(located_value.1).0;
        values.iter_mut().for_each(|(p, _)| {
            let mut new_loc = v_loc.clone();
            new_loc.append(p);
            *p = new_loc;
        });
        // in flatten, returned address_path should be filled up.
        LocatedWord(
            values
                .into_iter()
                .map(|(p, v)| (AddressPath::from(p).fill_up(), v))
                .collect(),
        )
    }
}

impl<'v, F: FieldExt> From<LocatedValue<'v, IndexedLocation<F>, Value<F>>> for LocatedWord<F> {
    fn from(located_value: LocatedValue<'v, IndexedLocation<F>, Value<F>>) -> LocatedWord<F> {
        // increase the sub index by 1, because position 0 is occupied by the container header.
        let sub_indexes = located_value
            .0
            .sub_indexes
            .iter()
            .map(|v| (*v + 1) as u128)
            .collect();
        let v_loc = Location::ValueLocation(located_value.0.value_loc)
            .to_address_path()
            .with_subpath(sub_indexes)
            .into_inner();
        let mut values = Word::from(located_value.1).0;
        values.iter_mut().for_each(|(p, _)| {
            let mut new_loc = v_loc.clone();
            new_loc.append(p);
            *p = new_loc;
        });
        LocatedWord(
            values
                .into_iter()
                .map(|(p, v)| (AddressPath::from(p).fill_up(), v))
                .collect(),
        )
    }
}

/// A header is added for the flattened value. Both value length and flattened value's length
/// are recorded in the header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader<F: FieldExt> {
    flattened_len: u16,
    len: u16,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ValueHeader<F> {
    pub fn new(flattened_len: usize, len: usize) -> Self {
        debug_assert!(flattened_len < u16::MAX as usize);
        debug_assert!(len < u16::MAX as usize);

        Self {
            flattened_len: flattened_len as u16,
            len: len as u16,
            _marker: PhantomData,
        }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flattened_len
    // bit[16..32], len
    pub fn value(&self) -> F {
        F::from_u128((self.flattened_len as u128) + ((self.len as u128) << 16))
    }
    pub fn expr(&self) -> Expression<F> {
        Expression::Constant(self.value())
    }
    pub fn flattened_len(&self) -> u16 {
        self.flattened_len
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn members(&self) -> (u16, u16) {
        (self.flattened_len, self.len)
    }

    // default ValueHeader for any simple value
    pub fn default_for_simple() -> Self {
        Self::new(2, 1)
    }

    // default ValueHeader for any reference value
    pub fn default_for_ref_val() -> Self {
        Self::new(LEN_OF_REFERENCE_VALUE, LEN_OF_REFERENCE_VALUE - 1)
    }
}

impl<F: FieldExt> From<ValueHeader<F>> for PrimitiveValue<F> {
    fn from(value: ValueHeader<F>) -> PrimitiveValue<F> {
        PrimitiveValue::U128(U128(value.value()))
    }
}

impl<F: FieldExt> From<F> for ValueHeader<F> {
    fn from(value: F) -> ValueHeader<F> {
        let flattened_len = (value.get_lower_128() & 0xFFFF) as usize;
        let len = ((value.get_lower_128() & 0xFFFF0000) >> 16) as usize;
        Self::new(flattened_len, len)
    }
}
