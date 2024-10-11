// Copyright (c) zkMove Authors

use crate::utility::{convert_u256_to_u128_pair, u256};
use crate::value::{
    AddressPath, Container, GlobalRef, IndexedLocation, IndexedRef, LocalRef, LocatedValue,
    Location, Reference, SimpleValue, Value, ValueLocation, DEPTH_OF_LOCATION_PATH,
};
use halo2_proofs::plonk::Expression;
use std::convert::{From, TryFrom, TryInto};
use types::Field;

pub const LEN_OF_REFERENCE_VALUE: usize = 4; // header + DEPTH_OF_LOCATION_PATH + addr_ext
pub const LEN_OF_SIMPLE_VALUE: usize = 3;
pub const HEADER_OFFSET: usize = 0;
pub const LOWER_FIELD_OFFSET: usize = 1;
pub const UPPER_FIELD_OFFSET: usize = 2;

/// To efficiently represent a complex value in the circuit, we defined 'FlattenedValue'.
///
/// It starts with a value header carrying type information, followed by simple values
/// flattened from the complex value.
#[derive(Clone, Debug)]
pub struct FlattenedValue(pub Vec<(Vec<u128>, SimpleValue)>);

impl From<&Value> for FlattenedValue {
    fn from(value: &Value) -> Self {
        match value {
            Value::Invalid => FlattenedValue(vec![]), // TODO: Issue #52
            Value::U8(_)
            | Value::U16(_)
            | Value::U32(_)
            | Value::U64(_)
            | Value::U128(_)
            | Value::Bool(_)
            | Value::Address(_) => {
                let simple = SimpleValue::try_from(value).expect("should not fail");
                FlattenedSimpleValue::from(simple).into()
            }
            Value::U256(u) => FlattenedU256::from(*u).into(),
            Value::Container(c) => FlattenedContainerValue::from(c).into(),
            Value::GlobalRef(_) | Value::IndexedRef(_) | Value::LocalRef(_) => {
                let reference = Reference::try_from(value).expect("should not fail");
                FlattenedReferenceValue::from(reference).into()
            }
        }
    }
}

impl FlattenedValue {
    // Compare with another flattened value. Return the position where
    // the first difference occurs, or return None, means that the two
    // values are the same.
    pub fn diff(&self, other: &Self) -> Option<usize> {
        if self.0.len() != other.0.len() {
            return Some(0); // header must be different
        }

        for (i, (addr_ext, value)) in self.0.iter().enumerate() {
            let (other_addr_ext, other_value) = &other.0[i];
            if addr_ext != other_addr_ext || value != other_value {
                return Some(i);
            }
        }
        None
    }

    // flatten addr_ext and simples into one vector
    // vec[i*2] = addr_ext[i], vec[i*2+1] = simple[i]
    pub fn field_values<F: Field>(&self) -> Vec<F> {
        self.0
            .iter()
            .flat_map(|(addr_ext, simple)| {
                let addr_path: AddressPath = AddressPath::from(addr_ext.clone());
                vec![
                    F::from_u128(addr_path.fold()),
                    simple.field_value().unwrap(),
                ]
            })
            .collect::<Vec<_>>()
    }
}

#[derive(Clone, Debug)]
pub struct FlattenedSimpleValue(pub [(Vec<u128>, SimpleValue); LEN_OF_SIMPLE_VALUE]);

impl From<SimpleValue> for FlattenedSimpleValue {
    fn from(value: SimpleValue) -> FlattenedSimpleValue {
        FlattenedSimpleValue([
            (vec![0u128], ValueHeader::default_for_simple().into()),
            (vec![1u128], value),
            (vec![2u128], SimpleValue::u128(0u128)),
        ])
    }
}

impl From<FlattenedSimpleValue> for FlattenedValue {
    fn from(value: FlattenedSimpleValue) -> FlattenedValue {
        FlattenedValue(value.0.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct FlattenedU256(pub [(Vec<u128>, SimpleValue); LEN_OF_SIMPLE_VALUE]);

impl From<u256::U256> for FlattenedU256 {
    fn from(value: u256::U256) -> FlattenedU256 {
        let f = convert_u256_to_u128_pair(&value);
        FlattenedU256([
            (vec![0u128], ValueHeader::default_for_u256().into()),
            (vec![1u128], SimpleValue::U128(f[1])),
            (vec![2u128], SimpleValue::U128(f[0])),
        ])
    }
}
impl From<FlattenedU256> for FlattenedValue {
    fn from(value: FlattenedU256) -> FlattenedValue {
        FlattenedValue(value.0.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct FlattenedReferenceValue(pub [(Vec<u128>, SimpleValue); LEN_OF_REFERENCE_VALUE]);

impl FlattenedReferenceValue {
    fn fold(simples: Vec<(Vec<u128>, SimpleValue)>) -> Self {
        let mut value: u128 = 0;
        for (i, (_, val)) in simples.iter().skip(DEPTH_OF_LOCATION_PATH + 1).enumerate() {
            // fold addr_ext into one cell
            let x = val.to_u128().expect("value should not be None.");
            value += x << (16 * i);
        }

        let mut new_ref_value = simples
            .into_iter()
            .take(LEN_OF_REFERENCE_VALUE)
            .collect::<Vec<_>>();

        let (address_path, _) = new_ref_value.pop().expect("value should not be None.");
        new_ref_value.push((address_path, SimpleValue::u128(value)));
        let flattened_ref_value: [(Vec<u128>, SimpleValue); LEN_OF_REFERENCE_VALUE] = new_ref_value
            .try_into()
            .unwrap_or_else(|v: Vec<(Vec<u128>, SimpleValue)>| {
                panic!(
                    "Expected a Vec of length {} but it was {}",
                    LEN_OF_REFERENCE_VALUE,
                    v.len()
                )
            });
        FlattenedReferenceValue(flattened_ref_value)
    }
}

impl From<Reference> for FlattenedReferenceValue {
    fn from(value: Reference) -> FlattenedReferenceValue {
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
                Location::ValueLocation(ValueLocation::Local(loc))
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
            .map(SimpleValue::U128)
            .collect::<Vec<_>>();

        simples.insert(0, ValueHeader::default_for_ref_val().into());
        let new_simples = simples
            .into_iter()
            .enumerate()
            .map(|(i, v)| (vec![i as u128], v))
            .collect::<Vec<_>>();
        FlattenedReferenceValue::fold(new_simples)
    }
}

impl From<FlattenedReferenceValue> for FlattenedValue {
    fn from(value: FlattenedReferenceValue) -> FlattenedValue {
        FlattenedValue(value.0.to_vec())
    }
}

#[derive(Clone, Debug)]
pub struct FlattenedContainerValue(pub Vec<(Vec<u128>, SimpleValue)>);

impl From<&Container> for FlattenedContainerValue {
    fn from(container: &Container) -> FlattenedContainerValue {
        let mut simples = Vec::new();
        for (idx, val) in container.0.borrow().iter().enumerate() {
            let mut sub_values = FlattenedValue::from(val).0;
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
        FlattenedContainerValue(simples)
    }
}

impl From<FlattenedContainerValue> for FlattenedValue {
    fn from(value: FlattenedContainerValue) -> FlattenedValue {
        FlattenedValue(value.0)
    }
}

#[derive(Clone, Debug)]
pub struct LocatedFlattenedValue(pub Vec<(AddressPath, SimpleValue)>);

impl<'v> From<LocatedValue<'v, ValueLocation, Value>> for LocatedFlattenedValue {
    fn from(located_value: LocatedValue<'v, ValueLocation, Value>) -> LocatedFlattenedValue {
        let v_loc = Location::ValueLocation(located_value.0)
            .to_address_path()
            .into_inner();
        let mut values = FlattenedValue::from(located_value.1).0;
        values.iter_mut().for_each(|(p, _)| {
            let mut new_loc = v_loc.clone();
            new_loc.append(p);
            *p = new_loc;
        });
        // in flatten, returned address_path should be filled up.
        LocatedFlattenedValue(
            values
                .into_iter()
                .map(|(p, v)| (AddressPath::from(p).fill_up(), v))
                .collect(),
        )
    }
}

impl<'v> From<LocatedValue<'v, IndexedLocation, Value>> for LocatedFlattenedValue {
    fn from(located_value: LocatedValue<'v, IndexedLocation, Value>) -> LocatedFlattenedValue {
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
        let mut values = FlattenedValue::from(located_value.1).0;
        values.iter_mut().for_each(|(p, _)| {
            let mut new_loc = v_loc.clone();
            new_loc.append(p);
            *p = new_loc;
        });
        LocatedFlattenedValue(
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
pub struct ValueHeader {
    flattened_len: u16,
    len: u16,
}

impl ValueHeader {
    pub fn new(flattened_len: usize, len: usize) -> Self {
        debug_assert!(flattened_len < u16::MAX as usize);
        debug_assert!(len < u16::MAX as usize);

        Self {
            flattened_len: flattened_len as u16,
            len: len as u16,
        }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flattened_len
    // bit[16..32], len
    pub fn value(&self) -> u128 {
        (self.flattened_len as u128) + ((self.len as u128) << 16)
    }

    pub fn field_value<F: Field>(&self) -> F {
        F::from_u128((self.flattened_len as u128) + ((self.len as u128) << 16))
    }

    pub fn expr<F: Field>(&self) -> Expression<F> {
        Expression::Constant(self.field_value())
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
        Self::new(3, 2)
    }

    // default ValueHeader for U256 value
    pub fn default_for_u256() -> Self {
        Self::new(3, 2)
    }

    // default ValueHeader for any reference value
    pub fn default_for_ref_val() -> Self {
        Self::new(LEN_OF_REFERENCE_VALUE, LEN_OF_REFERENCE_VALUE - 1)
    }
}

impl From<ValueHeader> for SimpleValue {
    fn from(value: ValueHeader) -> SimpleValue {
        SimpleValue::U128(value.value())
    }
}

impl<F: Field> From<F> for ValueHeader {
    fn from(value: F) -> ValueHeader {
        let flattened_len = (value.get_lower_128() & 0xFFFF) as usize;
        let len = ((value.get_lower_128() & 0xFFFF0000) >> 16) as usize;
        Self::new(flattened_len, len)
    }
}
