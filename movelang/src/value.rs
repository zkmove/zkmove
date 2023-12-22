// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use crate::account_address::AccountAddress;
use crate::utility::{
    convert_to_field, convert_u256_to_fe, convert_u256_to_field, decode_field_to_u256, move_div,
    move_rem, u256,
};
use crate::utility::{MoveValue, MoveValueType};
use crate::value_ext::{FlattenedContainerValue, FlattenedValue};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_base::halo2_proofs::circuit::Value as CircuitValue;
use move_binary_format::file_format::{StructDefInstantiationIndex, StructDefinitionIndex};
use move_core_types::account_address::AccountAddress as MoveAccountAddress;
pub use move_core_types::language_storage::{ModuleId, TypeTag};
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::ops::{Add, Deref, DerefMut, Div, Mul, Not, Rem, Sub};
use std::{cell::RefCell, rc::Rc};
use types::Field;

pub const NUM_OF_BYTES_U8: usize = 1;
pub const NUM_OF_BYTES_U16: usize = 2;
pub const NUM_OF_BYTES_U32: usize = 4;
pub const NUM_OF_BYTES_U64: usize = 8;
pub const NUM_OF_BYTES_U128: usize = 16;
pub const NUM_OF_BYTES_U256: usize = 32;
pub const DEPTH_OF_LOCATION_PATH: usize = 2; // max(global location, locals location, stack location)
pub const DEPTH_OF_ADDRESS_PATH: usize = DEPTH_OF_LOCATION_PATH + 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U8<F: Field>(pub F);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U16<F: Field>(pub F);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U32<F: Field>(pub F);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U64<F: Field>(pub F);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U128<F: Field>(pub F);

/// (upper 128 bit, lower 128 bit)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct U256<F: Field>(pub F, pub F);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Bool<F: Field>(pub F);

/// Index of a frame
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrameIndex(pub usize);

/// Index of a value in locals, or index of a member in the struct
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Index(pub usize);

#[derive(Clone, Debug)]
//todo: use 'Field' instead of 'u128'?
pub struct AddressPath<F: Field>(pub Vec<u128>, PhantomData<F>);
impl<F: Field> From<Vec<u128>> for AddressPath<F> {
    fn from(indexes: Vec<u128>) -> Self {
        AddressPath(indexes, PhantomData)
    }
}

impl<F: Field> AddressPath<F> {
    pub fn into_inner(self) -> Vec<u128> {
        self.0
    }
    pub fn as_inner(&self) -> &Vec<u128> {
        &self.0
    }
    pub fn extend(self, leaf: u128) -> Self {
        let mut path = self.into_inner();
        path.push(leaf);
        AddressPath(path, PhantomData)
    }
    pub fn with_subpath(mut self, mut subpath: Vec<u128>) -> Self {
        self.0.append(&mut subpath);
        self
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn fill_up(mut self) -> Self {
        let mut length = self.len();
        while length < DEPTH_OF_ADDRESS_PATH {
            self = self.extend(0);
            length = self.len();
        }
        self
    }
    // TODO: 'self' is not always a full address path. but this function assume it's a full path.
    // addr_ext begin from 3rd elements
    // 128bit(16 * 8) can keep 8 dimensions container address
    pub fn addr_ext(self) -> usize {
        let path = self.into_inner();
        let ret: u128 = path
            .iter()
            .enumerate()
            .skip(2)
            .map(|(i, v)| (*v << (16 * (i - 2))))
            .sum();
        ret as usize
    }
    /// fold AddressPath into u128
    pub fn fold(self) -> u128 {
        self.into_inner()
            .iter()
            .enumerate()
            .map(|(i, v)| (*v << (16 * i)))
            .sum()
    }
}

// impl<F: Field> U256<F> {
//     fn from(value: U256<F>) -> MoveValue {
//         MoveValue::U256(decode_field_to_u256(&[value.0, value.1]))
//     }
// }

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SimpleValue<F: Field> {
    U8(U8<F>),
    U16(U16<F>),
    U32(U32<F>),
    U64(U64<F>),
    U128(U128<F>),
    Bool(Bool<F>),
    Address(AccountAddress<F>),
}

impl<F: Field> From<SimpleValue<F>> for MoveValue {
    fn from(value: SimpleValue<F>) -> MoveValue {
        match value {
            SimpleValue::U8(field) => MoveValue::U8(field.0.get_lower_128() as u8),
            SimpleValue::U16(field) => MoveValue::U16(field.0.get_lower_128() as u16),
            SimpleValue::U32(field) => MoveValue::U32(field.0.get_lower_128() as u32),
            SimpleValue::U64(field) => MoveValue::U64(field.0.get_lower_128() as u64),
            SimpleValue::U128(field) => MoveValue::U128(field.0.get_lower_128()),
            SimpleValue::Bool(field) => MoveValue::Bool(field.0 == F::ONE),
            SimpleValue::Address(field) => {
                // FIXME: f -> bytes for address
                let mut bytes = 0u128.to_be_bytes().to_vec();
                bytes.append(&mut field.value().get_lower_128().to_be_bytes().to_vec());
                MoveValue::Address(MoveAccountAddress::from_bytes(bytes).unwrap())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Value<F: Field> {
    Invalid,
    /// The following is simple value
    U8(U8<F>),
    U16(U16<F>),
    U32(U32<F>),
    U64(U64<F>),
    U128(U128<F>),
    Bool(Bool<F>),
    Address(AccountAddress<F>),
    /// u256
    U256(U256<F>),
    /// struct representation
    Container(Container<F>),
    /// borrow global
    GlobalRef(GlobalRef<F>),
    /// borrow local
    LocalRef(LocalRef<F>),
    /// borrow field of a container
    IndexedRef(IndexedRef<F>),
}
/// Container is just a wrapper of vec contains its fields.
#[derive(Clone, Debug)]
pub struct Container<F: Field>(pub Rc<RefCell<Vec<Value<F>>>>);

/// Location of global struct.
#[derive(Clone, Copy, Debug)]
pub struct GlobalLocation<F: Field> {
    pub address: AccountAddress<F>,
    pub sd_index: GlobalResourceDefIndex,
}

#[derive(Clone, Copy, Debug)]
pub enum GlobalResourceDefIndex {
    StructDefinitionIndex(StructDefinitionIndex),
    StructDefInstantiationIndex(StructDefInstantiationIndex),
}

impl From<StructDefinitionIndex> for GlobalResourceDefIndex {
    fn from(d: StructDefinitionIndex) -> Self {
        GlobalResourceDefIndex::StructDefinitionIndex(d)
    }
}
impl From<StructDefInstantiationIndex> for GlobalResourceDefIndex {
    fn from(d: StructDefInstantiationIndex) -> Self {
        GlobalResourceDefIndex::StructDefInstantiationIndex(d)
    }
}

impl GlobalResourceDefIndex {
    pub fn to_u128(&self) -> u128 {
        match self {
            Self::StructDefinitionIndex(idx) => idx.0 as u128,
            GlobalResourceDefIndex::StructDefInstantiationIndex(idx) => (idx.0 as u128) << 16,
        }
    }
}

/// Location of local values(simple values or containers)
#[derive(Clone, Copy, Debug)]
pub struct LocalLocation {
    pub frame_index: FrameIndex,
    pub index: usize,
}

/// Location of stack values (simple values or containers)
#[derive(Clone, Copy, Debug)]
pub struct StackLocation {
    pub stack_index: usize,
}

/// Location of value stored in sub-fields of a container(in local or global, even in stack)
/// IndexedValue doesn't actually fit in our value locations.
/// we fake it as a location just to make value flatten easier.
#[derive(Clone, Debug)]
pub struct IndexedLocation<F: Field> {
    pub sub_indexes: Vec<usize>,
    pub value_loc: ValueLocation<F>,
}
impl<F: Field> IndexedLocation<F> {
    pub fn new(root_location: ValueLocation<F>, sub_indexes: Vec<usize>) -> Self {
        IndexedLocation {
            sub_indexes,
            value_loc: root_location,
        }
    }

    /// keep it private so it cannot be abused
    fn to_address_path(&self) -> AddressPath<F> {
        self.value_loc
            .to_address_path()
            .with_subpath(self.sub_indexes.iter().map(|v| *v as u128).collect())
    }
}

/// Location of value when it move/copy from one place to another place.
#[derive(Clone, Copy, Debug)]
pub enum ValueLocation<F: Field> {
    Stack(StackLocation),
    Local(LocalLocation),
    Global(GlobalLocation<F>),
}
impl<F: Field> ValueLocation<F> {
    fn to_address_path(self) -> AddressPath<F> {
        let indexes = match self {
            ValueLocation::Stack(loc) => vec![0_u128, loc.stack_index as u128],
            ValueLocation::Local(loc) => vec![loc.frame_index.0 as u128, loc.index as u128],
            ValueLocation::Global(loc) => vec![
                // FIXME: change this once we determine what to use in witness(finite field or plain value ?).
                loc.address.value().get_lower_128(),
                loc.sd_index.to_u128(),
            ],
        };
        indexes.into()
    }
}
impl<F: Field> Container<F> {
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }

    pub fn rc_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }
    pub fn vector(elems: impl IntoIterator<Item = Value<F>>) -> Self {
        Container(Rc::new(RefCell::new(elems.into_iter().collect())))
    }
    pub fn signer(x: AccountAddress<F>) -> Self {
        Container(Rc::new(RefCell::new(vec![Value::Address(x)])))
    }
    /// read_field return a deep_copy of the field.
    fn read_field(&self, element_idx: usize) -> VmResult<Value<F>> {
        let len = self.0.borrow().len();
        if element_idx >= len {
            return Err(
                RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                    "index out of bounds when get container element: index: {}, length: {}",
                    element_idx, len
                )),
            );
        }
        let v = self.0.borrow();
        let e = &v[element_idx];
        Ok(e.copy_value())
    }
    /// write_field write a value into the field of element_idx
    fn write_field(&self, element_idx: usize, v: Value<F>) -> VmResult<()> {
        let len = self.0.borrow().len();
        if element_idx >= len {
            return Err(
                RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                    "index out of bounds when write container element: index: {}, length: {}",
                    element_idx, len
                )),
            );
        }
        let mut c = self.0.borrow_mut();
        c[element_idx] = v;
        Ok(())
    }

    pub fn equals(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        for (v1, v2) in self.0.borrow().iter().zip(other.0.borrow().iter()) {
            if !v1.equals(v2) {
                return false;
            }
        }
        true
    }
}

impl<F: Field> From<LocalRef<F>> for Value<F> {
    fn from(v: LocalRef<F>) -> Self {
        Value::LocalRef(v)
    }
}
impl<F: Field> From<GlobalRef<F>> for Value<F> {
    fn from(v: GlobalRef<F>) -> Self {
        Value::GlobalRef(v)
    }
}
impl<F: Field> From<IndexedRef<F>> for Value<F> {
    fn from(v: IndexedRef<F>) -> Self {
        Value::IndexedRef(v)
    }
}
/// ContainerRef contains reference location of the underlying container.
/// It can also distinguish whether the container is local or global.
#[derive(Clone, Debug)]
pub enum ContainerRef<F: Field> {
    Global(GlobalLocation<F>, Container<F>),
    Local(LocalLocation, Container<F>),
}
impl<F: Field> ContainerRef<F> {
    pub fn location(&self) -> ValueLocation<F> {
        match self {
            ContainerRef::Global(loc, _) => ValueLocation::Global(*loc),
            ContainerRef::Local(loc, _) => ValueLocation::Local(*loc),
        }
    }
    pub fn container(&self) -> Container<F> {
        match self {
            ContainerRef::Global(_, c) => c.clone(),
            ContainerRef::Local(_, c) => c.clone(),
        }
    }
}

#[derive(Debug)]
pub enum Reference<F: Field> {
    /// borrow global
    GlobalRef(GlobalRef<F>),
    /// borrow local
    LocalRef(LocalRef<F>),
    /// borrow field of a container
    IndexedRef(IndexedRef<F>),
}
impl<F: Field> From<Reference<F>> for Value<F> {
    fn from(r: Reference<F>) -> Self {
        match r {
            Reference::GlobalRef(g) => Value::GlobalRef(g),
            Reference::LocalRef(l) => Value::LocalRef(l),
            Reference::IndexedRef(i) => Value::IndexedRef(i),
        }
    }
}

impl<F: Field> TryFrom<&Value<F>> for Reference<F> {
    type Error = RuntimeError;

    fn try_from(v: &Value<F>) -> VmResult<Reference<F>> {
        match v {
            Value::GlobalRef(g) => Ok(Reference::GlobalRef(g.clone())),
            Value::LocalRef(l) => Ok(Reference::LocalRef(l.clone())),
            Value::IndexedRef(i) => Ok(Reference::IndexedRef(i.clone())),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl<F: Field> Reference<F> {
    /// return address_path of the value which is referenced by this ref
    /// NOTICE: returned address_path is not filled up.
    pub fn value_address_path(&self) -> AddressPath<F> {
        match self {
            Self::GlobalRef(g) => ValueLocation::Global(g.loc).to_address_path(),
            Self::LocalRef(l) => ValueLocation::Local(l.loc).to_address_path(),
            Self::IndexedRef(i) => IndexedLocation {
                sub_indexes: i.sub_indexes.clone(),
                value_loc: i.container_ref.location(),
            }
            .to_address_path(),
        }
    }
    /// read_ref returns a deep_copyed value
    pub fn read_ref(&self) -> VmResult<Value<F>> {
        Ok(match self {
            Reference::GlobalRef(g) => Value::Container(g.read_ref()?),
            Reference::LocalRef(l) => l.read_ref()?,
            Reference::IndexedRef(l) => l.read_ref()?,
        })
    }
    /// write_ref write a value to the reference.
    pub fn write_ref(&self, v: Value<F>) -> VmResult<()> {
        match self {
            Reference::GlobalRef(g) => g.write_ref(v),
            Reference::LocalRef(l) => l.write_ref(v),
            Reference::IndexedRef(l) => l.write_ref(v),
        }
    }
    /// try_borrow_field will trait reference as a struct ref, and try to borrow it's field.
    pub fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef<F>> {
        match self {
            Reference::GlobalRef(g) => g.try_borrow_field(element_idx),
            Reference::LocalRef(l) => l.try_borrow_field(element_idx),
            Reference::IndexedRef(l) => l.try_borrow_field(element_idx),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Location<F: Field> {
    ValueLocation(ValueLocation<F>),
    IndexedLocation(IndexedLocation<F>),
}

impl<F: Field> Location<F> {
    pub fn to_address_path(&self) -> AddressPath<F> {
        match self {
            Location::ValueLocation(l) => l.to_address_path(),
            Location::IndexedLocation(l) => l.to_address_path(),
        }
    }
}

#[derive(Debug)]
pub enum VectorRef<F: Field> {
    /// vector in locals
    LocalRef(LocalRef<F>),
    /// vector as a field of a container
    IndexedRef(IndexedRef<F>),
}

impl<F: Field> VectorRef<F> {
    /// read_ref returns a deep_copyed value
    pub fn read_ref(&self) -> VmResult<Value<F>> {
        Ok(match self {
            VectorRef::LocalRef(l) => l.read_ref()?,
            VectorRef::IndexedRef(i) => i.read_ref()?,
        })
    }
    /// return address_path of the vector which is referenced by this ref
    /// NOTICE: returned address_path is not filled up.
    pub fn value_address_path(&self) -> AddressPath<F> {
        match self {
            Self::LocalRef(l) => ValueLocation::Local(l.loc).to_address_path(),
            Self::IndexedRef(i) => IndexedLocation {
                sub_indexes: i.sub_indexes.clone(),
                value_loc: i.container_ref.location(),
            }
            .to_address_path(),
        }
    }

    pub fn container(&self) -> VmResult<Container<F>> {
        match self {
            VectorRef::LocalRef(l) => {
                let mut ref_val = l.refer.borrow_mut();
                match ref_val.deref_mut() {
                    Value::Container(c) => Ok(c.clone()),
                    _ => Err(RuntimeError::new(StatusCode::TypeMismatch)
                        .with_message("cannot get length for a non container value".to_string())),
                }
            }
            VectorRef::IndexedRef(i) => {
                let mut cur_value = i.container_ref.container();
                for idx in &i.sub_indexes {
                    cur_value = {
                        let mut val = cur_value.0.borrow_mut();
                        let sub_val = val
                            .get_mut(*idx)
                            .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;

                        match sub_val {
                            Value::Container(c) => c.clone(),
                            _ => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
                        }
                    };
                }
                Ok(cur_value)
            }
        }
    }

    pub fn location(&self) -> VmResult<Location<F>> {
        match self {
            VectorRef::LocalRef(l) => Ok(Location::ValueLocation(ValueLocation::Local(l.loc))),
            VectorRef::IndexedRef(i) => {
                let loc = IndexedLocation {
                    sub_indexes: i.sub_indexes.clone(),
                    value_loc: i.container_ref.location(),
                };
                Ok(Location::IndexedLocation(loc))
            }
        }
    }

    pub fn is_global(&self) -> bool {
        match self {
            VectorRef::LocalRef(_) => false,
            VectorRef::IndexedRef(i) => {
                let loc = IndexedLocation {
                    sub_indexes: i.sub_indexes.clone(),
                    value_loc: i.container_ref.location(),
                };
                match loc.value_loc {
                    ValueLocation::Stack(_) => unreachable!(),
                    ValueLocation::Local(_) => false,
                    ValueLocation::Global(_) => true,
                }
            }
        }
    }

    pub fn current_and_parent_container_headers(
        &self,
    ) -> VmResult<Vec<(Location<F>, SimpleValue<F>)>> {
        let mut res = Vec::new();
        match self {
            VectorRef::LocalRef(l) => {
                let ref_val = l.read_ref()?;
                match ref_val {
                    Value::Container(_) => {
                        let flattened_value = FlattenedValue::from(&ref_val).0;
                        let (_, header_value) =
                            flattened_value.first().expect("header should not be none");
                        res.push((
                            Location::ValueLocation(ValueLocation::Local(l.loc)),
                            *header_value,
                        ))
                    }
                    _ => {
                        return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(
                            "cannot get length for a non container value".to_string(),
                        ))
                    }
                }
            }
            VectorRef::IndexedRef(i) => {
                let value_loc = i.container_ref.location();
                let mut cur_value = i.container_ref.container();
                let flattened_value = FlattenedContainerValue::from(&cur_value).0;
                let (_, header_value) = flattened_value.first().expect("header should not be none");
                res.push((Location::ValueLocation(value_loc), *header_value));

                let mut cur_sub_indexes = Vec::new();
                for idx in &i.sub_indexes {
                    cur_value = {
                        let mut val = cur_value.0.borrow_mut();
                        let sub_val = val
                            .get_mut(*idx)
                            .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;

                        match sub_val {
                            Value::Container(c) => c.clone(),
                            _ => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
                        }
                    };
                    // increase the sub index by 1, because position 0 is occupied by the container header.
                    cur_sub_indexes.push(*idx + 1);
                    let loc = IndexedLocation {
                        sub_indexes: cur_sub_indexes.clone(),
                        value_loc,
                    };
                    let flattened_value = FlattenedContainerValue::from(&cur_value).0;
                    let (_, header_value) =
                        flattened_value.first().expect("header should not be none");
                    res.push((Location::IndexedLocation(loc), *header_value));
                }
            }
        }
        Ok(res)
    }

    pub fn try_borrow_elem(&self, element_idx: usize) -> VmResult<IndexedRef<F>> {
        match self {
            VectorRef::LocalRef(l) => l.try_borrow_field(element_idx),
            VectorRef::IndexedRef(l) => l.try_borrow_field(element_idx),
        }
    }

    pub fn length(&self) -> VmResult<usize> {
        let ref_val = self.read_ref()?;
        match ref_val {
            Value::Container(c) => Ok(c.0.borrow().len()),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("cannot get length for a non container value".to_string())),
        }
    }

    pub fn push_back(&self, elem: Value<F>) -> VmResult<()> {
        self.container()?.0.borrow_mut().push(elem);
        Ok(())
    }

    pub fn pop(&self) -> VmResult<Value<F>> {
        let c = self.container()?;
        let mut values = c.0.borrow_mut();
        match values.pop() {
            Some(v) => Ok(v),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)
                .with_message("index out of bounds when get container element".to_string())),
        }
    }

    pub fn swap(&self, idx1: usize, idx2: usize) -> VmResult<()> {
        let c = self.container()?;
        let mut v = c.0.borrow_mut();
        if idx1 >= v.len() || idx2 >= v.len() {
            return Err(RuntimeError::new(StatusCode::OutOfBounds)
                .with_message("index out of bounds".to_string()));
        }
        v.swap(idx1, idx2);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRef<F: Field> {
    pub loc: GlobalLocation<F>,
    pub refer: Container<F>,
}

impl<F: Field> GlobalRef<F> {
    fn read_ref(&self) -> VmResult<Container<F>> {
        Ok(self.refer.copy_value())
    }
    fn write_ref(&self, v: Value<F>) -> VmResult<()> {
        let c = match v {
            Value::Container(c) => c,
            _ => {
                return Err(RuntimeError::new(StatusCode::TypeMismatch)
                    .with_message("failed to write_ref: container type mismatch".to_string()))
            }
        };
        debug_assert_eq!(Rc::strong_count(&c.0), 1);
        *self.refer.0.borrow_mut() = c.0.take();
        Ok(())
    }

    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef<F>> {
        let len = self.refer.0.borrow().len();
        if element_idx >= len {
            return Err(
                RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                    "index out of bounds when borrowing container element: index: {}, length: {}",
                    element_idx, len
                )),
            );
        }
        Ok(IndexedRef {
            sub_indexes: vec![element_idx],
            container_ref: ContainerRef::Global(self.loc, self.refer.clone()),
        })
    }
    pub fn equals(&self, other: &Self) -> bool {
        self.refer.equals(&other.refer)
    }
}

#[derive(Clone, Debug)]
pub struct LocalRef<F: Field> {
    pub loc: LocalLocation,
    pub refer: Rc<RefCell<Value<F>>>,
}

impl<F: Field> LocalRef<F> {
    fn read_ref(&self) -> VmResult<Value<F>> {
        Ok(self.refer.borrow().copy_value())
    }
    fn write_ref(&self, v: Value<F>) -> VmResult<()> {
        let mut this_value = self.refer.borrow_mut();
        match (this_value.deref_mut(), v) {
            (Value::Bool(t), Value::Bool(v)) => {
                *t = v;
            }
            (Value::U8(t), Value::U8(v)) => {
                *t = v;
            }
            (Value::U16(t), Value::U16(v)) => {
                *t = v;
            }
            (Value::U32(t), Value::U32(v)) => {
                *t = v;
            }
            (Value::U64(t), Value::U64(v)) => {
                *t = v;
            }
            (Value::U128(t), Value::U128(v)) => {
                *t = v;
            }
            (Value::U256(t), Value::U256(v)) => {
                *t = v;
            }
            (Value::Address(t), Value::Address(v)) => {
                *t = v;
            }
            (Value::Container(t), Value::Container(v)) => {
                *t.0.borrow_mut() = v.0.take();
            }
            // TODO: support write a reference?
            _ => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
        Ok(())
    }

    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef<F>> {
        let v = self.refer.borrow();
        match v.deref() {
            Value::Container(c) => {
                let len = c.0.borrow().len();
                if element_idx >= len {
                    return Err(
                        RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                            "index out of bounds when borrowing container element: index: {}, length: {}",
                            element_idx, len
                        )),
                    );
                }
                Ok(IndexedRef {
                    sub_indexes: vec![element_idx],
                    container_ref: ContainerRef::Local(self.loc, c.clone()),
                })
            }
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(
                "cannot borrow field from a reference to non container value".to_string(),
            )),
        }
    }
    pub fn equals(&self, other: &Self) -> bool {
        self.refer.borrow().equals(&other.refer.borrow())
    }
}

#[derive(Clone, Debug)]
pub struct IndexedRef<F: Field> {
    pub sub_indexes: Vec<usize>,
    pub container_ref: ContainerRef<F>,
}

impl<F: Field> IndexedRef<F> {
    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef<F>> {
        let this_value = self.read_ref()?;

        match this_value {
            Value::Container(c) => {
                let len = c.0.borrow().len();
                if element_idx >= len {
                    return Err(
                        RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                            "index out of bounds when borrowing container element: index: {}, length: {}",
                            element_idx, len
                        )),
                    );
                }
                Ok(IndexedRef {
                    sub_indexes: {
                        let mut idxes = self.sub_indexes.clone();
                        idxes.push(element_idx);
                        idxes
                    },
                    container_ref: self.container_ref.clone(),
                })
            }
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(
                "cannot borrow field from a reference to non container value".to_string(),
            )),
        }
    }

    /// read_ref return the value which is a deep copy
    fn read_ref(&self) -> VmResult<Value<F>> {
        let mut cur_value = self.container_ref.container();
        debug_assert_ne!(self.sub_indexes.len(), 0);
        let (last, prev) = self.sub_indexes.split_last().unwrap();
        for idx in prev {
            let field = cur_value.read_field(*idx)?;
            match field {
                Value::Container(c) => cur_value = c,
                _ => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
            }
        }
        cur_value.read_field(*last)
    }

    fn write_ref(&self, v: Value<F>) -> VmResult<()> {
        let mut cur_value = self.container_ref.container();
        debug_assert_ne!(self.sub_indexes.len(), 0);
        let (last, prev) = self.sub_indexes.split_last().unwrap();
        for idx in prev {
            cur_value = {
                let v = cur_value.0.borrow();
                let v = v
                    .get(*idx)
                    .ok_or_else(|| RuntimeError::new(StatusCode::OutOfBounds))?;

                match v {
                    Value::Container(c) => c.clone(),
                    _ => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
                }
            };
        }
        cur_value.write_field(*last, v)
    }
    pub fn equals(&self, other: &Self) -> bool {
        let v = self.read_ref().expect("read_ref should not fail");
        v.equals(&other.read_ref().expect("read_ref should not fail"))
    }
}

impl<F: Field> From<IndexedRef<F>> for VmResult<(IndexedLocation<F>, Value<F>)> {
    fn from(indexed_ref: IndexedRef<F>) -> Self {
        let val = indexed_ref.read_ref()?;
        let loc = IndexedLocation {
            sub_indexes: indexed_ref.sub_indexes,
            value_loc: indexed_ref.container_ref.location(),
        };
        Ok((loc, val))
    }
}

impl<F: Field> From<U256<F>> for Value<F> {
    fn from(v: U256<F>) -> Self {
        Value::U256(v)
    }
}

impl<F: Field> TryFrom<&Value<F>> for U256<F> {
    type Error = RuntimeError;

    fn try_from(value: &Value<F>) -> VmResult<U256<F>> {
        match value {
            Value::U256(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl<F: Field> From<MoveValue> for U256<F> {
    fn from(value: MoveValue) -> Self {
        match value {
            MoveValue::U256(v) => {
                let f = convert_u256_to_field::<F>(&v);
                U256(f[0], f[1])
            }
            _ => unimplemented!("not supported move value, {}", value),
        }
    }
}

impl<F: Field> U256<F> {
    pub fn new(x: u256::U256) -> Self {
        let v = convert_u256_to_field::<F>(&x);
        Self(v[0], v[1])
    }

    pub fn value(&self) -> Option<(F, F)> {
        match self {
            Self(v0, v1) => Some((*v0, *v1)),
        }
    }

    pub fn ty(&self) -> MoveValueType {
        MoveValueType::U256
    }
}

impl<F: Field> From<SimpleValue<F>> for Value<F> {
    fn from(simple: SimpleValue<F>) -> Self {
        match simple {
            SimpleValue::U8(v) => Value::U8(v),
            SimpleValue::U16(v) => Value::U16(v),
            SimpleValue::U32(v) => Value::U32(v),
            SimpleValue::U64(v) => Value::U64(v),
            SimpleValue::U128(v) => Value::U128(v),
            SimpleValue::Bool(v) => Value::Bool(v),
            SimpleValue::Address(v) => Value::Address(v),
        }
    }
}

impl<F: Field> TryFrom<&Value<F>> for SimpleValue<F> {
    type Error = RuntimeError;

    fn try_from(value: &Value<F>) -> VmResult<SimpleValue<F>> {
        match value {
            Value::U8(v) => Ok(SimpleValue::U8(*v)),
            Value::U16(v) => Ok(SimpleValue::U16(*v)),
            Value::U32(v) => Ok(SimpleValue::U32(*v)),
            Value::U64(v) => Ok(SimpleValue::U64(*v)),
            Value::U128(v) => Ok(SimpleValue::U128(*v)),
            Value::Bool(v) => Ok(SimpleValue::Bool(*v)),
            Value::Address(v) => Ok(SimpleValue::Address(*v)),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl<F: Field> From<MoveValue> for SimpleValue<F> {
    fn from(value: MoveValue) -> Self {
        match value {
            MoveValue::U8(v) => SimpleValue::u8(v),
            MoveValue::U16(v) => SimpleValue::u16(v),
            MoveValue::U32(v) => SimpleValue::u32(v),
            MoveValue::U64(v) => SimpleValue::u64(v),
            MoveValue::U128(v) => SimpleValue::u128(v),
            MoveValue::Bool(v) => SimpleValue::bool(v),
            MoveValue::Address(v) => SimpleValue::address(v.into()),
            _ => unimplemented!("not supported move value, {}", value),
        }
    }
}

impl<F: Field> SimpleValue<F> {
    pub fn bool(x: bool) -> Self {
        let value = if x { F::ONE } else { F::ZERO };
        Self::Bool(Bool(value))
    }
    pub fn u8(x: u8) -> Self {
        let value = F::from_u128(x as u128);
        Self::U8(U8(value))
    }
    pub fn u16(x: u16) -> Self {
        let value = F::from_u128(x as u128);
        Self::U16(U16(value))
    }
    pub fn u32(x: u32) -> Self {
        let value = F::from_u128(x as u128);
        Self::U32(U32(value))
    }
    pub fn u64(x: u64) -> Self {
        let value = F::from_u128(x as u128);
        Self::U64(U64(value))
    }
    pub fn u128(x: u128) -> Self {
        let value = F::from_u128(x);
        Self::U128(U128(value))
    }
    pub fn address(x: AccountAddress<F>) -> Self {
        Self::Address(x)
    }

    pub fn value(&self) -> Option<F> {
        match self {
            Self::U8(v) => Some(v.0),
            Self::U16(v) => Some(v.0),
            Self::U32(v) => Some(v.0),
            Self::U64(v) => Some(v.0),
            Self::U128(v) => Some(v.0),
            Self::Bool(v) => Some(v.0),
            Self::Address(addr) => Some(addr.value()),
        }
    }

    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::U8(_) => MoveValueType::U8,
            Self::U16(_) => MoveValueType::U16,
            Self::U32(_) => MoveValueType::U32,
            Self::U64(_) => MoveValueType::U64,
            Self::U128(_) => MoveValueType::U128,
            Self::Bool(_) => MoveValueType::Bool,
            Self::Address(_) => MoveValueType::Address,
        }
    }
}

impl<F: Field> From<MoveValue> for Value<F> {
    fn from(value: MoveValue) -> Self {
        match value {
            MoveValue::U8(v) => Value::u8(v),
            MoveValue::U64(v) => Value::u64(v),
            MoveValue::U128(v) => Value::u128(v),
            MoveValue::Bool(v) => Value::bool(v),
            MoveValue::Address(v) => Value::address(v.into()),
            MoveValue::Vector(v) => {
                Value::Container(Container::vector(v.into_iter().map(Into::into)))
            }
            _ => unimplemented!("not supported move value, {}", value),
        }
    }
}

impl<F: Field> Value<F> {
    pub fn new(value: F, ty: MoveValueType) -> VmResult<Self> {
        match ty {
            MoveValueType::U8 => Ok(Self::U8(U8(value))),
            MoveValueType::U16 => Ok(Self::U16(U16(value))),
            MoveValueType::U32 => Ok(Self::U32(U32(value))),
            MoveValueType::U64 => Ok(Self::U64(U64(value))),
            MoveValueType::U128 => Ok(Self::U128(U128(value))),
            MoveValueType::Bool => Ok(Self::Bool(Bool(value))),
            MoveValueType::Signer => Ok(Self::signer(AccountAddress::new(value))),
            MoveValueType::Address => Ok(Self::address(AccountAddress::new(value))),
            _ => unimplemented!(),
        }
    }

    /// convert from Field into Value<F>
    pub fn new_u256(value: [F; 2]) -> Self {
        Self::U256(U256(value[0], value[1]))
    }

    pub fn bool(x: bool) -> Self {
        let value = if x { F::ONE } else { F::ZERO };
        Self::Bool(Bool(value))
    }
    pub fn u8(x: u8) -> Self {
        let value = F::from_u128(x as u128);
        Self::U8(U8(value))
    }
    pub fn u16(x: u16) -> Self {
        let value = F::from_u128(x as u128);
        Self::U16(U16(value))
    }
    pub fn u32(x: u32) -> Self {
        let value = F::from_u128(x as u128);
        Self::U32(U32(value))
    }
    pub fn u64(x: u64) -> Self {
        let value = F::from_u128(x as u128);
        Self::U64(U64(value))
    }
    pub fn u128(x: u128) -> Self {
        let value = F::from_u128(x);
        Self::U128(U128(value))
    }
    /// convert from u256::U256 into Value<F>
    pub fn u256(x: u256::U256) -> Self {
        let value = convert_u256_to_field::<F>(&x);
        Self::U256(U256(value[0], value[1]))
    }

    pub fn address(x: AccountAddress<F>) -> Self {
        Self::Address(x)
    }

    pub fn signer(x: AccountAddress<F>) -> Self {
        Self::Container(Container::signer(x))
    }
    pub fn vector_u8(elems: impl IntoIterator<Item = u8>) -> Self {
        Self::Container(Container::vector(elems.into_iter().map(|e| Self::u8(e))))
    }

    /// TODO: figure out a better way to convert to rust value.
    pub fn as_vector_u8(&self) -> VmResult<Vec<u8>> {
        match self {
            Self::Container(Container(vs)) => {
                let mut ret_ = vec![];
                for v in vs.borrow().iter() {
                    ret_.push(v.copy_value().castu8()?.value().unwrap().get_lower_128() as u8);
                }
                Ok(ret_)
            }
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)),
        }
    }

    pub fn container(elements: Vec<Value<F>>) -> Self {
        Self::Container(Container::vector(elements))
    }

    pub fn value(&self) -> Option<F> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => Some(v.0),
            Self::U16(v) => Some(v.0),
            Self::U32(v) => Some(v.0),
            Self::U64(v) => Some(v.0),
            Self::U128(v) => Some(v.0),
            Self::Bool(v) => Some(v.0),
            Self::Address(addr) => Some(addr.value()),
            _ => unreachable!(),
        }
    }

    pub fn value_u256(&self) -> Option<[F; 2]> {
        match self {
            Self::U256(v) => Some([v.0, v.1]),
            _ => unreachable!(),
        }
    }

    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::U8(_) => MoveValueType::U8,
            Self::U16(_) => MoveValueType::U16,
            Self::U32(_) => MoveValueType::U32,
            Self::U64(_) => MoveValueType::U64,
            Self::U128(_) => MoveValueType::U128,
            Self::U256(_) => MoveValueType::U256,
            Self::Bool(_) => MoveValueType::Bool,
            _ => unimplemented!(),
        }
    }
    pub fn num_of_bytes(ty: MoveValueType) -> Self {
        let len = match ty {
            MoveValueType::U8 => NUM_OF_BYTES_U8,
            MoveValueType::U16 => NUM_OF_BYTES_U16,
            MoveValueType::U32 => NUM_OF_BYTES_U32,
            MoveValueType::U64 => NUM_OF_BYTES_U64,
            MoveValueType::U128 => NUM_OF_BYTES_U128,
            MoveValueType::U256 => NUM_OF_BYTES_U256,
            _ => unimplemented!(),
        };
        let value = F::from_u128(len as u128);
        Self::U8(U8(value))
    }

    /// Cast the value into simple value if it's simple
    /// NOTICE: restrict access to `pub(self)` so that outside use flatten or flattened_value_len instead of this.
    pub fn cast_simple(&self) -> Option<SimpleValue<F>> {
        Some(match self {
            Value::U8(v) => SimpleValue::U8(*v),
            Value::U16(v) => SimpleValue::U16(*v),
            Value::U32(v) => SimpleValue::U32(*v),
            Value::U64(v) => SimpleValue::U64(*v),
            Value::U128(v) => SimpleValue::U128(*v),
            Value::Bool(v) => SimpleValue::Bool(*v),
            Value::Address(v) => SimpleValue::Address(*v),
            _ => return None,
        })
    }
}

/// A located value
#[derive(Debug)]
pub struct LocatedValue<'v, L, V>(/* loc */ pub L, /* v */ pub &'v V);

impl<F: Field> PartialEq for Value<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl<F: Field> Eq for Value<F> {}

impl<F: Field> Add for U256<F> {
    type Output = VmResult<Self>;

    fn add(self, b: U256<F>) -> Self::Output {
        // implement add based on checked_add API to check arithmetic overflow
        let v = self.value().unwrap();
        let lhs = decode_field_to_u256(&[v.0, v.1]);
        let v = b.value().unwrap();
        let rhs = decode_field_to_u256(&[v.0, v.1]);

        let res = u256::U256::checked_add(lhs, rhs).expect("arithmetic error found");
        let c = U256::new(res);
        Ok(c)
    }
}
impl<F: Field> Sub for U256<F> {
    type Output = VmResult<Self>;

    fn sub(self, b: U256<F>) -> Self::Output {
        // implement sub based on checked_sub API to check arithmetic overflow
        let v = self.value().unwrap();
        let lhs = decode_field_to_u256(&[v.0, v.1]);
        let v = b.value().unwrap();
        let rhs = decode_field_to_u256(&[v.0, v.1]);

        let res = u256::U256::checked_sub(lhs, rhs).expect("arithmetic error found");
        let c = U256::new(res);
        Ok(c)
    }
}
impl<F: Field> Mul for U256<F> {
    type Output = VmResult<Self>;

    fn mul(self, b: U256<F>) -> Self::Output {
        // implement mul based on checked_mul API to check arithmetic overflow
        let v = self.value().unwrap();
        let lhs = decode_field_to_u256(&[v.0, v.1]);
        let v = b.value().unwrap();
        let rhs = decode_field_to_u256(&[v.0, v.1]);

        let res = u256::U256::checked_mul(lhs, rhs).expect("arithmetic error found");
        let c = U256::new(res);
        Ok(c)
    }
}
impl<F: Field> Div for U256<F> {
    type Output = VmResult<Self>;

    fn div(self, b: U256<F>) -> Self::Output {
        // implement div based on checked_div API to check arithmetic overflow
        let v = self.value().unwrap();
        let lhs = decode_field_to_u256(&[v.0, v.1]);
        let v = b.value().unwrap();
        let rhs = decode_field_to_u256(&[v.0, v.1]);

        let res = u256::U256::checked_div(lhs, rhs).expect("arithmetic error found");
        let c = U256::new(res);
        Ok(c)
    }
}

impl<F: Field> Rem for U256<F> {
    type Output = VmResult<Self>;

    fn rem(self, b: U256<F>) -> Self::Output {
        // implement rem based on checked_rem API to check arithmetic overflow
        let v = self.value().unwrap();
        let lhs = decode_field_to_u256(&[v.0, v.1]);
        let v = b.value().unwrap();
        let rhs = decode_field_to_u256(&[v.0, v.1]);

        let res = u256::U256::checked_rem(lhs, rhs).expect("arithmetic error found");
        let c = U256::new(res);
        Ok(c)
    }
}
impl<F: Field> Not for U256<F> {
    type Output = VmResult<Value<F>>;

    fn not(self) -> Self::Output {
        let v = self.value().expect("arithmetic error found");
        let res = if v.0.is_zero_vartime() && v.1.is_zero_vartime() {
            F::ONE
        } else {
            F::ZERO
        };

        let c = Value::new(res, MoveValueType::Bool)?;
        Ok(c)
    }
}

impl<F: Field> Add for Value<F> {
    type Output = VmResult<Self>;

    fn add(self, b: Value<F>) -> Self::Output {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let v = u256::U256::checked_add(lhs, rhs).expect("arithmetic error found");
            Ok(Value::u256(v))
        } else {
            // implement add based on checked_add API to check arithmetic overflow
            // let value = self.value().and_then(|a| b.value().map(|b| a + b));
            let lhs = self.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = match (self.ty(), b.ty()) {
                (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                    u8::checked_add(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
                ),
                (MoveValueType::U16, MoveValueType::U16) => F::from_u128(
                    u16::checked_add(lhs as u16, rhs as u16).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U32, MoveValueType::U32) => F::from_u128(
                    u32::checked_add(lhs as u32, rhs as u32).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                    u64::checked_add(lhs as u64, rhs as u64).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U128, MoveValueType::U128) => {
                    F::from_u128(u128::checked_add(lhs, rhs).expect("arithmetic error found"))
                }
                (_, _) => unimplemented!(),
            };
            let c = Value::new(value, self.ty())?;
            Ok(c)
        }
    }
}

impl<F: Field> Sub for Value<F> {
    type Output = VmResult<Self>;

    fn sub(self, b: Value<F>) -> Self::Output {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let v = u256::U256::checked_sub(lhs, rhs).expect("arithmetic error found");
            Ok(Value::u256(v))
        } else {
            // implement sub based on checked_sub API to check arithmetic overflow
            // let value = self.value().and_then(|a| b.value().map(|b| a - b));
            let lhs = self.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = match (self.ty(), b.ty()) {
                (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                    u8::checked_sub(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
                ),
                (MoveValueType::U16, MoveValueType::U16) => F::from_u128(
                    u16::checked_sub(lhs as u16, rhs as u16).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U32, MoveValueType::U32) => F::from_u128(
                    u32::checked_sub(lhs as u32, rhs as u32).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                    u64::checked_sub(lhs as u64, rhs as u64).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U128, MoveValueType::U128) => {
                    F::from_u128(u128::checked_sub(lhs, rhs).expect("arithmetic error found"))
                }
                (_, _) => unimplemented!(),
            };
            let c = Value::new(value, self.ty())?;
            Ok(c)
        }
    }
}

impl<F: Field> Mul for Value<F> {
    type Output = VmResult<Self>;

    fn mul(self, b: Value<F>) -> Self::Output {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let v = u256::U256::checked_mul(lhs, rhs).expect("arithmetic error found");
            Ok(Value::u256(v))
        } else {
            // implement mul based on checked_mul API to check arithmetic overflow
            // let value = self.value().and_then(|a| b.value().map(|b| a * b));
            let lhs = self.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = match (self.ty(), b.ty()) {
                (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                    u8::checked_mul(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
                ),
                (MoveValueType::U16, MoveValueType::U16) => F::from_u128(
                    u16::checked_mul(lhs as u16, rhs as u16).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U32, MoveValueType::U32) => F::from_u128(
                    u32::checked_mul(lhs as u32, rhs as u32).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                    u64::checked_mul(lhs as u64, rhs as u64).expect("arithmetic error found")
                        as u128,
                ),
                (MoveValueType::U128, MoveValueType::U128) => {
                    F::from_u128(u128::checked_mul(lhs, rhs).expect("arithmetic error found"))
                }
                (_, _) => unimplemented!(),
            };
            let c = Value::new(value, self.ty())?;
            Ok(c)
        }
    }
}

impl<F: Field> Div for Value<F> {
    type Output = VmResult<Self>;

    fn div(self, b: Value<F>) -> Self::Output {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let v = u256::U256::checked_div(lhs, rhs).expect("arithmetic error found");
            Ok(Value::u256(v))
        } else {
            let l_move: Option<MoveValue> = self.cast_simple().map(Into::into);
            let r_move: Option<MoveValue> = b.into();
            match (l_move, r_move) {
                (Some(l), Some(r)) => {
                    let quo = move_div(l, r)?;
                    let v = convert_to_field::<F>(quo);
                    let value = Value::new(v, self.ty())?;
                    Ok(value)
                }
                _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                    .with_message("Move value should not be None".to_string())),
            }
        }
    }
}

impl<F: Field> Rem for Value<F> {
    type Output = VmResult<Self>;

    fn rem(self, b: Value<F>) -> Self::Output {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let v = u256::U256::checked_rem(lhs, rhs).expect("arithmetic error found");
            Ok(Value::u256(v))
        } else {
            let l_move: Option<MoveValue> = self.cast_simple().map(Into::into);
            let r_move: Option<MoveValue> = b.into();
            match (l_move, r_move) {
                (Some(l), Some(r)) => {
                    let rem = move_rem(l, r)?;
                    let v = convert_to_field::<F>(rem);
                    let value = Value::new(v, self.ty())?;
                    Ok(value)
                }
                _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                    .with_message("Move value should not be None".to_string())),
            }
        }
    }
}

impl<F: Field> Not for Value<F> {
    type Output = VmResult<Self>;

    fn not(self) -> Self::Output {
        let value = if self.is_zero() { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }
}

impl<F: Field> Value<F> {
    pub fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => true,
            (Self::U8(v1), Self::U8(v2)) => v1.0 == v2.0,
            (Self::U16(v1), Self::U16(v2)) => v1.0 == v2.0,
            (Self::U32(v1), Self::U32(v2)) => v1.0 == v2.0,
            (Self::U64(v1), Self::U64(v2)) => v1.0 == v2.0,
            (Self::U128(v1), Self::U128(v2)) => v1.0 == v2.0,
            (Self::U256(v1), Self::U256(v2)) => (v1.0 == v2.0) && (v1.1 == v2.1),
            (Self::Bool(v1), Self::Bool(v2)) => v1.0 == v2.0,
            (Self::Address(a1), Self::Address(a2)) => a1.value() == a2.value(),
            (Self::Container(c1), Self::Container(c2)) => c1.equals(c2),
            (Self::GlobalRef(r1), Self::GlobalRef(r2)) => r1.equals(r2),
            (Self::LocalRef(r1), Self::LocalRef(r2)) => r1.equals(r2),
            (Self::IndexedRef(r1), Self::IndexedRef(r2)) => r1.equals(r2),
            _ => false,
        }
    }

    pub fn less_than(&self, other: &Self) -> VmResult<bool> {
        // fixme. maybe there is better implemtentation here.
        if self.ty() == MoveValueType::U256 && other.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = other.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            Ok(lhs < rhs)
        } else {
            match (self.value(), other.value()) {
                (Some(v1), Some(v2)) => Ok(v1 < v2),
                _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
            }
        }
    }

    pub fn less_equal(&self, other: &Self) -> VmResult<bool> {
        // fixme. maybe there is better implemtentation here.
        if self.ty() == MoveValueType::U256 && other.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = other.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            Ok(lhs <= rhs)
        } else {
            match (self.value(), other.value()) {
                (Some(v1), Some(v2)) => Ok(v1 <= v2),
                _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
            }
        }
    }

    pub fn greater_than(&self, other: &Self) -> VmResult<bool> {
        // fixme. maybe there is better implemtentation here.
        if self.ty() == MoveValueType::U256 && other.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = other.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            Ok(lhs > rhs)
        } else {
            match (self.value(), other.value()) {
                (Some(v1), Some(v2)) => Ok(v1 > v2),
                _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
            }
        }
    }

    pub fn greater_equal(&self, other: &Self) -> VmResult<bool> {
        // fixme. maybe there is better implemtentation here.
        if self.ty() == MoveValueType::U256 && other.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = other.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            Ok(lhs >= rhs)
        } else {
            match (self.value(), other.value()) {
                (Some(v1), Some(v2)) => Ok(v1 >= v2),
                _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
            }
        }
    }

    pub fn is_zero(&self) -> bool {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            v[0].is_zero_vartime() && v[1].is_zero_vartime()
        } else {
            match self.value() {
                Some(v) => v.is_zero_vartime(),
                None => false,
            }
        }
    }

    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::U8(_)
                | Self::U16(_)
                | Self::U32(_)
                | Self::U64(_)
                | Self::U128(_)
                | Self::U256(_)
        )
    }
    pub fn is_reference(&self) -> bool {
        matches!(
            self,
            Self::GlobalRef(_) | Self::LocalRef(_) | Self::IndexedRef(_)
        )
    }

    pub fn castu8(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u8".to_string()));
        }

        match self {
            Self::U8(_) => Ok(self),
            Self::U16(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u16({}) to u8", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U8)
                }
            }
            Self::U32(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u32({}) to u8", val)))
                } else {
                    // Self::u32(val as u32, None)
                    Value::new(F::from_u128(val), MoveValueType::U8)
                }
            }
            Self::U64(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u8", val)))
                } else {
                    // Self::u64(val as u64, None)
                    Value::new(F::from_u128(val), MoveValueType::U8)
                }
            }
            Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u8", val)))
                } else {
                    // Self::u128(val, None)
                    Value::new(F::from_u128(val), MoveValueType::U8)
                }
            }
            Self::U256(x) => {
                let val = decode_field_to_u256(&[x.0, x.1]);
                if val > u256::U256::from(std::u8::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u8", val)))
                } else {
                    Value::new(
                        F::from_u128(val.unchecked_as_u8() as u128),
                        MoveValueType::U8,
                    )
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn castu16(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u16".to_string()));
        }

        match self {
            Self::U8(_) | Self::U16(_) => {
                let val = self.value().unwrap().get_lower_128();
                Value::new(F::from_u128(val), MoveValueType::U16)
            }
            Self::U32(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u16::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u32({}) to u16", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U16)
                }
            }
            Self::U64(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u16::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u16", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U16)
                }
            }
            Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u16::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u16", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U16)
                }
            }
            Self::U256(x) => {
                let val = decode_field_to_u256(&[x.0, x.1]);
                if val > u256::U256::from(std::u16::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u16", val)))
                } else {
                    Value::new(
                        F::from_u128(val.unchecked_as_u16() as u128),
                        MoveValueType::U16,
                    )
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn castu32(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u32".to_string()));
        }

        match self {
            Self::U8(_) | Self::U16(_) | Self::U32(_) => {
                let val = self.value().unwrap().get_lower_128();
                Value::new(F::from_u128(val), MoveValueType::U32)
            }
            Self::U64(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u32::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u32", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U32)
                }
            }
            Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u32::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u32", val)))
                } else {
                    Value::new(F::from_u128(val), MoveValueType::U32)
                }
            }
            Self::U256(x) => {
                let val = decode_field_to_u256(&[x.0, x.1]);
                if val > u256::U256::from(std::u32::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u32", val)))
                } else {
                    Value::new(
                        F::from_u128(val.unchecked_as_u32() as u128),
                        MoveValueType::U32,
                    )
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn castu64(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u64".to_string()));
        }

        match self {
            Self::U8(_) | Self::U16(_) | Self::U32(_) | Self::U64(_) => {
                let val = self.value().unwrap().get_lower_128();
                Value::new(F::from_u128(val), MoveValueType::U64)
            }
            Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                if val > (std::u64::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u64", val)))
                } else {
                    // Self::u128(val, None)
                    Value::new(F::from_u128(val), MoveValueType::U64)
                }
            }
            Self::U256(x) => {
                let val = decode_field_to_u256(&[x.0, x.1]);
                if val > u256::U256::from(std::u64::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u64", val)))
                } else {
                    Value::new(
                        F::from_u128(val.unchecked_as_u64() as u128),
                        MoveValueType::U64,
                    )
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn castu128(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u128".to_string()));
        }

        match self {
            Self::U8(_) | Self::U16(_) | Self::U32(_) | Self::U64(_) | Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                Value::new(F::from_u128(val), MoveValueType::U128)
            }
            Self::U256(x) => {
                let val = decode_field_to_u256(&[x.0, x.1]);
                if val > u256::U256::from(std::u128::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u128", val)))
                } else {
                    Value::new(F::from_u128(val.unchecked_as_u128()), MoveValueType::U128)
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn castu256(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u256".to_string()));
        }

        match self {
            Self::U8(_) | Self::U16(_) | Self::U32(_) | Self::U64(_) | Self::U128(_) => {
                let val = self.value().unwrap().get_lower_128();
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U256(_) => Ok(self),
            _ => unreachable!(),
        }
    }

    pub fn div_rem(&self, other: Value<F>) -> VmResult<(Value<F>, Value<F>)> {
        if self.ty() == MoveValueType::U256 {
            let v = self.value_u256().unwrap();
            let l_move = Some(MoveValue::U256(decode_field_to_u256(&v)));
            let r_move: Option<MoveValue> = other.into();
            match (l_move, r_move) {
                (Some(l), Some(r)) => {
                    let quo = move_div(l.clone(), r.clone())?;
                    let rem = move_rem(l, r)?;
                    match (quo, rem) {
                        (MoveValue::U256(q), MoveValue::U256(r)) => {
                            let quo_value = Value::u256(q);
                            let rem_value = Value::u256(r);
                            Ok((quo_value, rem_value))
                        }
                        _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                            .with_message("Move value should not be None".to_string())),
                    }
                }
                _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                    .with_message("Move value should not be None".to_string())),
            }
        } else {
            let l_move: Option<MoveValue> = self.cast_simple().map(Into::into);
            let r_move: Option<MoveValue> = other.into();
            match (l_move, r_move) {
                (Some(l), Some(r)) => {
                    let quo = move_div(l.clone(), r.clone())?;
                    let rem = move_rem(l, r)?;
                    let quo_field = convert_to_field::<F>(quo);
                    let rem_field = convert_to_field::<F>(rem);
                    let quo_value = Value::new(quo_field, self.ty())?;
                    let rem_value = Value::new(rem_field, self.ty())?;
                    Ok((quo_value, rem_value))
                }
                _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                    .with_message("Move value should not be None".to_string())),
            }
        }
    }

    pub fn eq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.equals(&b) { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn neq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if !a.equals(&b) { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn lt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lt = a.less_than(&b)?;
        let value = if lt { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn le(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let le = a.less_equal(&b)?;
        let value = if le { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn gt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let gt = a.greater_than(&b)?;
        let value = if gt { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn ge(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let ge = a.greater_equal(&b)?;
        let value = if ge { F::ONE } else { F::ZERO };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn shift_checked(a: Value<F>, b: Value<F>, shift_left: bool) -> VmResult<Value<F>> {
        // NOTICE: check type of a and b is not necessary here, as bytecode verifier already check that.
        // but we still do it due to the lack of verifier currently.
        if !a.is_integer() {
            return Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("expect value of integer type".to_string()));
        }
        if b.ty() != MoveValueType::U8 {
            return Err(RuntimeError::new(StatusCode::InvalidValue)
                .with_message("expect value of u8 type".to_string()));
        }
        let n_bits = b.value().unwrap().get_lower_128() as u8;
        let max_bits = match a.ty() {
            MoveValueType::U8 => 7,
            MoveValueType::U16 => 15,
            MoveValueType::U32 => 31,
            MoveValueType::U64 => 63,
            MoveValueType::U128 => 127,
            MoveValueType::U256 => 255,
            _ => unreachable!(),
        };
        if n_bits > max_bits {
            return Err(RuntimeError::new(StatusCode::ArithmeticError)
                .with_message("exceed max shift bits".to_string()));
        }
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let shift_value = if shift_left {
                lhs << n_bits
            } else {
                lhs >> n_bits
            };
            Ok(Value::u256(shift_value))
        } else {
            let lhs = a.value().unwrap().get_lower_128();
            let shift_value = if shift_left {
                lhs << n_bits
            } else {
                lhs >> n_bits
            };
            Value::new(F::from_u128(shift_value), a.ty())
        }
    }

    pub fn shl_checked(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        Self::shift_checked(a, b, true)
    }
    pub fn shr_checked(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        Self::shift_checked(a, b, false)
    }

    pub fn bit_and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        if !a.is_integer() || !b.is_integer() {
            return Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("expect value of integer type".to_string()));
        }
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let result = convert_u256_to_field::<F>(&(lhs & rhs));
            let value = Value::new_u256(result);
            Ok(value)
        } else {
            let lhs = a.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = F::from_u128(lhs & rhs);
            let value = Value::new(value, a.ty())?;
            Ok(value)
        }
    }

    pub fn bit_or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        if !a.is_integer() || !b.is_integer() {
            return Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("expect value of integer type".to_string()));
        }
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let result = convert_u256_to_field::<F>(&(lhs | rhs));
            let value = Value::new_u256(result);
            Ok(value)
        } else {
            let lhs = a.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = F::from_u128(lhs | rhs);
            let value = Value::new(value, a.ty())?;
            Ok(value)
        }
    }

    pub fn xor(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        if !a.is_integer() || !b.is_integer() {
            return Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("expect value of integer type".to_string()));
        }
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let result = convert_u256_to_field::<F>(&(lhs ^ rhs));
            let value = Value::new_u256(result);
            Ok(value)
        } else {
            let lhs = a.value().unwrap().get_lower_128();
            let rhs = b.value().unwrap().get_lower_128();
            let value = F::from_u128(lhs ^ rhs);
            let value = Value::new(value, a.ty())?;
            Ok(value)
        }
    }

    pub fn and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() || b.is_zero() {
            F::ZERO
        } else {
            F::ONE
        };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() && b.is_zero() {
            F::ZERO
        } else {
            F::ONE
        };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn delta_invert(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let del_invert = if lhs == rhs {
                F::ONE
            } else {
                // fixme. how to deal with two fields here?
                let delta = convert_u256_to_fe::<F>(lhs - rhs);
                delta.invert().unwrap()
            };
            let value = Value::new(del_invert, MoveValueType::U128)?;
            Ok(value)
        } else {
            let delta_invert = if a.value() == b.value() {
                F::ONE
            } else {
                let delta = a.value().unwrap() - b.value().unwrap();
                delta.invert().unwrap()
            };

            let value = Value::new(delta_invert, a.ty())?;
            Ok(value)
        }
    }

    pub fn diff(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        if a.ty() == MoveValueType::U256 {
            let v = a.value_u256().unwrap();
            let lhs = decode_field_to_u256(&v);
            let v = b.value_u256().unwrap();
            let rhs = decode_field_to_u256(&v);
            let diff = lhs.wrapping_sub(rhs);
            let value = Value::new_u256(convert_u256_to_field::<F>(&diff));
            Ok(value)
        } else {
            let lhs = a.value().unwrap();
            let rhs = b.value().unwrap();
            let range = F::from(2).pow([(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);
            let range_or_zero = if lhs < rhs { range } else { F::ZERO };
            let diff = (lhs - rhs) + range_or_zero;
            let value = Value::new(diff, a.ty())?;
            Ok(value)
        }
    }
}

impl<F: Field> From<Value<F>> for Option<MoveValue> {
    fn from(value: Value<F>) -> Option<MoveValue> {
        value.cast_simple().map(Into::into)
    }
}

impl<F: Field> From<Value<F>> for CircuitValue<F> {
    fn from(value: Value<F>) -> CircuitValue<F> {
        match value.value() {
            Some(v) => CircuitValue::known(v),
            None => CircuitValue::unknown(),
        }
    }
}

impl<F: Field> Value<F> {
    /// copy value
    /// - For simple value, it copy the value.
    /// - For reference, it copy the pointer, and ref the container.
    /// - For container, it does a deep copy of all the underlying values.
    pub fn copy_value(&self) -> Self {
        match self {
            Self::Invalid => Self::Invalid,
            Self::U8(v) => Self::U8(*v),
            Self::U16(v) => Self::U16(*v),
            Self::U32(v) => Self::U32(*v),
            Self::U64(v) => Self::U64(*v),
            Self::U128(v) => Self::U128(*v),
            Self::U256(v) => Self::U256(*v),
            Self::Bool(v) => Self::Bool(*v),

            Self::GlobalRef(r) => Self::GlobalRef(r.clone()),
            Self::LocalRef(r) => Self::LocalRef(r.clone()),
            Self::IndexedRef(r) => Self::IndexedRef(r.clone()),

            Self::Address(addr) => Self::Address(*addr),
            Self::Container(c) => Self::Container(c.copy_value()),
        }
    }
}

impl<F: Field> Container<F> {
    pub fn copy_value(&self) -> Self {
        Self(Rc::new(RefCell::new(
            self.0.borrow().iter().map(|v| v.copy_value()).collect(),
        )))
    }
}

impl<F: Field> Value<F> {
    pub fn into_account_address(self) -> VmResult<AccountAddress<F>> {
        match self {
            Value::Address(address) => Ok(address),
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as AccountAddress".to_string())),
        }
    }
}

#[derive(Debug)]
pub struct ContainerValue<F: Field>(Vec<Value<F>>);

impl<F: Field> ContainerValue<F> {
    pub fn pack(values: Vec<Value<F>>) -> Self {
        Self(values)
    }

    pub fn unpack(self) -> Vec<Value<F>> {
        self.0
    }
}

// Clean - the value was only read.
// Dirty - the value was possibly modified.
#[derive(Debug, Clone, Copy)]
pub enum GlobalDataStatus {
    Clean,
    Dirty,
}

#[derive(Debug, Clone)]
pub enum GlobalValue<F: Field> {
    /// No resource resides in this slot or in storage.
    None,
    /// A resource has been published to this slot and it did not previously exist in storage.
    Fresh { fields: Rc<RefCell<Vec<Value<F>>>> },
    /// A resource resides in this slot and also in storage. The status flag indicates whether
    /// it has potentially been altered.
    Cached {
        fields: Rc<RefCell<Vec<Value<F>>>>,
        status: Rc<RefCell<GlobalDataStatus>>,
    },
    /// A resource used to exist in storage but has been deleted by the current transaction.
    Deleted,
}

impl<F: Field> GlobalValue<F> {
    pub fn none() -> Self {
        GlobalValue::None
    }

    fn fresh(val: Value<F>) -> VmResult<Self> {
        match val {
            Value::Container(Container(fields)) => Ok(Self::Fresh { fields }),
            _ => Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("not a resource type".to_string()),
            ),
        }
    }

    fn cached(val: Value<F>, status: GlobalDataStatus) -> VmResult<Self> {
        match val {
            Value::Container(Container(fields)) => {
                let status = Rc::new(RefCell::new(status));
                Ok(Self::Cached { fields, status })
            }
            _ => Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("not a resource type".to_string()),
            ),
        }
    }

    pub fn move_from(&mut self) -> VmResult<Value<F>> {
        let fields = match self {
            Self::None | Self::Deleted => return Err(RuntimeError::new(StatusCode::MissingData)),
            Self::Fresh { .. } => match std::mem::replace(self, Self::None) {
                Self::Fresh { fields } => fields,
                _ => unreachable!(),
            },
            Self::Cached { .. } => match std::mem::replace(self, Self::Deleted) {
                Self::Cached { fields, .. } => fields,
                _ => unreachable!(),
            },
        };
        if Rc::strong_count(&fields) != 1 {
            return Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("moving global resource with dangling reference".to_string()),
            );
        }
        Ok(Value::Container(Container(fields)))
    }

    pub fn move_to(&mut self, val: Value<F>) -> VmResult<()> {
        match self {
            Self::Fresh { .. } | Self::Cached { .. } => {
                return Err(RuntimeError::new(StatusCode::ResourceAlreadyExists))
            }
            Self::None => *self = Self::fresh(val)?,
            Self::Deleted => *self = Self::cached(val, GlobalDataStatus::Dirty)?,
        }
        Ok(())
    }

    pub fn exists(&self) -> VmResult<bool> {
        match self {
            Self::Fresh { .. } | Self::Cached { .. } => Ok(true),
            Self::None | Self::Deleted => Ok(false),
        }
    }

    pub fn borrow_global(
        &self,
        address: AccountAddress<F>,
        sd_index: GlobalResourceDefIndex,
    ) -> VmResult<GlobalRef<F>> {
        match self {
            Self::None | Self::Deleted => Err(RuntimeError::new(StatusCode::MissingData)),
            Self::Fresh { fields } => Ok(GlobalRef {
                loc: GlobalLocation { address, sd_index },
                refer: Container(Rc::clone(fields)),
            }),

            Self::Cached { fields, status: _ } => Ok(GlobalRef {
                loc: GlobalLocation { address, sd_index },
                refer: Container(Rc::clone(fields)),
            }),
        }
    }
}
