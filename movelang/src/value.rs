// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use crate::account_address::AccountAddress;
use crate::utility::{convert_u256_to_u128_pair, u256};
use crate::utility::{MoveValue, MoveValueType};
use crate::value_ext::{FlattenedContainerValue, FlattenedValue};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_base::halo2_proofs::circuit::Value as CircuitValue;
use move_binary_format::file_format::{StructDefInstantiationIndex, StructDefinitionIndex};
use move_core_types::account_address::AccountAddress as MoveAccountAddress;
pub use move_core_types::language_storage::{ModuleId, TypeTag};
use std::convert::TryFrom;
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

/// Index of a frame
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrameIndex(pub usize);

/// Index of a value in locals, or index of a member in the struct
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Index(pub usize);

#[derive(Clone, Debug)]
//todo: use 'Field' instead of 'u128'?
pub struct AddressPath(pub Vec<u128>);
impl From<Vec<u128>> for AddressPath {
    fn from(indexes: Vec<u128>) -> Self {
        AddressPath(indexes)
    }
}

impl AddressPath {
    pub fn into_inner(self) -> Vec<u128> {
        self.0
    }
    pub fn as_inner(&self) -> &Vec<u128> {
        &self.0
    }
    pub fn extend(self, leaf: u128) -> Self {
        let mut path = self.into_inner();
        path.push(leaf);
        AddressPath(path)
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SimpleValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Bool(bool),
    Address(AccountAddress),
}

impl From<SimpleValue> for MoveValue {
    fn from(value: SimpleValue) -> MoveValue {
        match value {
            SimpleValue::U8(v) => MoveValue::U8(v),
            SimpleValue::U16(v) => MoveValue::U16(v),
            SimpleValue::U32(v) => MoveValue::U32(v),
            SimpleValue::U64(v) => MoveValue::U64(v),
            SimpleValue::U128(v) => MoveValue::U128(v),
            SimpleValue::Bool(v) => MoveValue::Bool(v),
            SimpleValue::Address(v) => {
                // FIXME: f -> bytes for address
                let mut bytes = 0u128.to_be_bytes().to_vec();
                bytes.append(&mut v.value().to_be_bytes().to_vec());
                MoveValue::Address(MoveAccountAddress::from_bytes(bytes).unwrap())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Value {
    Invalid,
    /// The following is simple value
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Bool(bool),
    Address(AccountAddress),
    /// u256
    U256(u256::U256),
    /// struct representation
    Container(Container),
    /// borrow global
    GlobalRef(GlobalRef),
    /// borrow local
    LocalRef(LocalRef),
    /// borrow field of a container
    IndexedRef(IndexedRef),
}
/// Container is just a wrapper of vec contains its fields.
#[derive(Clone, Debug)]
pub struct Container(pub Rc<RefCell<Vec<Value>>>);

/// Location of global struct.
#[derive(Clone, Copy, Debug)]
pub struct GlobalLocation {
    pub address: AccountAddress,
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
pub struct IndexedLocation {
    pub sub_indexes: Vec<usize>,
    pub value_loc: ValueLocation,
}
impl IndexedLocation {
    pub fn new(root_location: ValueLocation, sub_indexes: Vec<usize>) -> Self {
        IndexedLocation {
            sub_indexes,
            value_loc: root_location,
        }
    }

    /// keep it private so it cannot be abused
    fn to_address_path(&self) -> AddressPath {
        self.value_loc
            .to_address_path()
            .with_subpath(self.sub_indexes.iter().map(|v| *v as u128).collect())
    }
}

/// Location of value when it move/copy from one place to another place.
#[derive(Clone, Copy, Debug)]
pub enum ValueLocation {
    Stack(StackLocation),
    Local(LocalLocation),
    Global(GlobalLocation),
}
impl ValueLocation {
    fn to_address_path(self) -> AddressPath {
        let indexes = match self {
            ValueLocation::Stack(loc) => vec![0_u128, loc.stack_index as u128],
            ValueLocation::Local(loc) => vec![loc.frame_index.0 as u128, loc.index as u128],
            ValueLocation::Global(loc) => vec![loc.address.value(), loc.sd_index.to_u128()],
        };
        indexes.into()
    }
}
impl Container {
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.borrow().is_empty()
    }

    pub fn rc_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }
    pub fn vector(elems: impl IntoIterator<Item = Value>) -> Self {
        Container(Rc::new(RefCell::new(elems.into_iter().collect())))
    }
    pub fn signer(x: AccountAddress) -> Self {
        Container(Rc::new(RefCell::new(vec![Value::Address(x)])))
    }
    /// read_field return a deep_copy of the field.
    fn read_field(&self, element_idx: usize) -> VmResult<Value> {
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
    fn write_field(&self, element_idx: usize, v: Value) -> VmResult<()> {
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

impl From<LocalRef> for Value {
    fn from(v: LocalRef) -> Self {
        Value::LocalRef(v)
    }
}
impl From<GlobalRef> for Value {
    fn from(v: GlobalRef) -> Self {
        Value::GlobalRef(v)
    }
}
impl From<IndexedRef> for Value {
    fn from(v: IndexedRef) -> Self {
        Value::IndexedRef(v)
    }
}
/// ContainerRef contains reference location of the underlying container.
/// It can also distinguish whether the container is local or global.
#[derive(Clone, Debug)]
pub enum ContainerRef {
    Global(GlobalLocation, Container),
    Local(LocalLocation, Container),
}
impl ContainerRef {
    pub fn location(&self) -> ValueLocation {
        match self {
            ContainerRef::Global(loc, _) => ValueLocation::Global(*loc),
            ContainerRef::Local(loc, _) => ValueLocation::Local(*loc),
        }
    }
    pub fn container(&self) -> Container {
        match self {
            ContainerRef::Global(_, c) => c.clone(),
            ContainerRef::Local(_, c) => c.clone(),
        }
    }
}

#[derive(Debug)]
pub enum Reference {
    /// borrow global
    GlobalRef(GlobalRef),
    /// borrow local
    LocalRef(LocalRef),
    /// borrow field of a container
    IndexedRef(IndexedRef),
}
impl From<Reference> for Value {
    fn from(r: Reference) -> Self {
        match r {
            Reference::GlobalRef(g) => Value::GlobalRef(g),
            Reference::LocalRef(l) => Value::LocalRef(l),
            Reference::IndexedRef(i) => Value::IndexedRef(i),
        }
    }
}

impl TryFrom<&Value> for Reference {
    type Error = RuntimeError;

    fn try_from(v: &Value) -> VmResult<Reference> {
        match v {
            Value::GlobalRef(g) => Ok(Reference::GlobalRef(g.clone())),
            Value::LocalRef(l) => Ok(Reference::LocalRef(l.clone())),
            Value::IndexedRef(i) => Ok(Reference::IndexedRef(i.clone())),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl Reference {
    /// return address_path of the value which is referenced by this ref
    /// NOTICE: returned address_path is not filled up.
    pub fn value_address_path(&self) -> AddressPath {
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
    pub fn read_ref(&self) -> VmResult<Value> {
        Ok(match self {
            Reference::GlobalRef(g) => Value::Container(g.read_ref()?),
            Reference::LocalRef(l) => l.read_ref()?,
            Reference::IndexedRef(l) => l.read_ref()?,
        })
    }
    /// write_ref write a value to the reference.
    pub fn write_ref(&self, v: Value) -> VmResult<()> {
        match self {
            Reference::GlobalRef(g) => g.write_ref(v),
            Reference::LocalRef(l) => l.write_ref(v),
            Reference::IndexedRef(l) => l.write_ref(v),
        }
    }
    /// try_borrow_field will trait reference as a struct ref, and try to borrow it's field.
    pub fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef> {
        match self {
            Reference::GlobalRef(g) => g.try_borrow_field(element_idx),
            Reference::LocalRef(l) => l.try_borrow_field(element_idx),
            Reference::IndexedRef(l) => l.try_borrow_field(element_idx),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Location {
    ValueLocation(ValueLocation),
    IndexedLocation(IndexedLocation),
}

impl Location {
    pub fn to_address_path(&self) -> AddressPath {
        match self {
            Location::ValueLocation(l) => l.to_address_path(),
            Location::IndexedLocation(l) => l.to_address_path(),
        }
    }
}

#[derive(Debug)]
pub enum VectorRef {
    /// vector in locals
    LocalRef(LocalRef),
    /// vector as a field of a container
    IndexedRef(IndexedRef),
}

impl VectorRef {
    /// read_ref returns a deep_copyed value
    pub fn read_ref(&self) -> VmResult<Value> {
        Ok(match self {
            VectorRef::LocalRef(l) => l.read_ref()?,
            VectorRef::IndexedRef(i) => i.read_ref()?,
        })
    }
    /// return address_path of the vector which is referenced by this ref
    /// NOTICE: returned address_path is not filled up.
    pub fn value_address_path(&self) -> AddressPath {
        match self {
            Self::LocalRef(l) => ValueLocation::Local(l.loc).to_address_path(),
            Self::IndexedRef(i) => IndexedLocation {
                sub_indexes: i.sub_indexes.clone(),
                value_loc: i.container_ref.location(),
            }
            .to_address_path(),
        }
    }

    pub fn container(&self) -> VmResult<Container> {
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

    pub fn location(&self) -> VmResult<Location> {
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

    pub fn current_and_parent_container_headers(&self) -> VmResult<Vec<(Location, SimpleValue)>> {
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

    pub fn try_borrow_elem(&self, element_idx: usize) -> VmResult<IndexedRef> {
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

    pub fn push_back(&self, elem: Value) -> VmResult<()> {
        self.container()?.0.borrow_mut().push(elem);
        Ok(())
    }

    pub fn pop(&self) -> VmResult<Value> {
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
pub struct GlobalRef {
    pub loc: GlobalLocation,
    pub refer: Container,
}

impl GlobalRef {
    fn read_ref(&self) -> VmResult<Container> {
        Ok(self.refer.copy_value())
    }
    fn write_ref(&self, v: Value) -> VmResult<()> {
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

    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef> {
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
pub struct LocalRef {
    pub loc: LocalLocation,
    pub refer: Rc<RefCell<Value>>,
}

impl LocalRef {
    fn read_ref(&self) -> VmResult<Value> {
        Ok(self.refer.borrow().copy_value())
    }
    fn write_ref(&self, v: Value) -> VmResult<()> {
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

    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef> {
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
pub struct IndexedRef {
    pub sub_indexes: Vec<usize>,
    pub container_ref: ContainerRef,
}

impl IndexedRef {
    fn try_borrow_field(&self, element_idx: usize) -> VmResult<IndexedRef> {
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
    fn read_ref(&self) -> VmResult<Value> {
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

    fn write_ref(&self, v: Value) -> VmResult<()> {
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

impl From<IndexedRef> for VmResult<(IndexedLocation, Value)> {
    fn from(indexed_ref: IndexedRef) -> Self {
        let val = indexed_ref.read_ref()?;
        let loc = IndexedLocation {
            sub_indexes: indexed_ref.sub_indexes,
            value_loc: indexed_ref.container_ref.location(),
        };
        Ok((loc, val))
    }
}

impl From<SimpleValue> for Value {
    fn from(simple: SimpleValue) -> Self {
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

impl TryFrom<&Value> for SimpleValue {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<SimpleValue> {
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

impl From<MoveValue> for SimpleValue {
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

impl SimpleValue {
    pub fn bool(x: bool) -> Self {
        Self::Bool(x)
    }
    pub fn u8(x: u8) -> Self {
        Self::U8(x)
    }
    pub fn u16(x: u16) -> Self {
        Self::U16(x)
    }
    pub fn u32(x: u32) -> Self {
        Self::U32(x)
    }
    pub fn u64(x: u64) -> Self {
        Self::U64(x)
    }
    pub fn u128(x: u128) -> Self {
        Self::U128(x)
    }
    pub fn address(x: AccountAddress) -> Self {
        Self::Address(x)
    }

    pub fn to_u128(&self) -> Option<u128> {
        match self {
            Self::U8(v) => Some(*v as u128),
            Self::U16(v) => Some(*v as u128),
            Self::U32(v) => Some(*v as u128),
            Self::U64(v) => Some(*v as u128),
            Self::U128(v) => Some(*v),
            Self::Bool(v) => Some(*v as u128),
            Self::Address(addr) => Some(addr.value()),
        }
    }

    pub fn field_value<F: Field>(&self) -> Option<F> {
        match self {
            Self::U8(v) => Some(F::from_u128(*v as u128)),
            Self::U16(v) => Some(F::from_u128(*v as u128)),
            Self::U32(v) => Some(F::from_u128(*v as u128)),
            Self::U64(v) => Some(F::from_u128(*v as u128)),
            Self::U128(v) => Some(F::from_u128(*v)),
            Self::Bool(v) => Some(F::from_u128(*v as u128)),
            Self::Address(addr) => Some(addr.field_value()),
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

impl From<MoveValue> for Value {
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

impl Value {
    pub fn bool(x: bool) -> Self {
        Self::Bool(x)
    }
    pub fn u8(x: u8) -> Self {
        Self::U8(x)
    }
    pub fn u16(x: u16) -> Self {
        Self::U16(x)
    }
    pub fn u32(x: u32) -> Self {
        Self::U32(x)
    }
    pub fn u64(x: u64) -> Self {
        Self::U64(x)
    }
    pub fn u128(x: u128) -> Self {
        Self::U128(x)
    }
    pub fn u256(x: u256::U256) -> Self {
        Self::U256(x)
    }

    pub fn address(x: AccountAddress) -> Self {
        Self::Address(x)
    }

    pub fn signer(x: AccountAddress) -> Self {
        Self::Container(Container::signer(x))
    }
    pub fn vector_u8(elems: impl IntoIterator<Item = u8>) -> Self {
        Self::Container(Container::vector(elems.into_iter().map(Self::u8)))
    }

    /// TODO: figure out a better way to convert to rust value.
    pub fn as_vector_u8(&self) -> VmResult<Vec<u8>> {
        match self {
            Self::Container(Container(vs)) => {
                let mut ret_ = vec![];
                for v in vs.borrow().iter() {
                    ret_.push(v.copy_value().castu8()?.to_u128().unwrap() as u8);
                }
                Ok(ret_)
            }
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)),
        }
    }

    pub fn container(elements: Vec<Value>) -> Self {
        Self::Container(Container::vector(elements))
    }

    pub fn to_u128(&self) -> Option<u128> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => Some(*v as u128),
            Self::U16(v) => Some(*v as u128),
            Self::U32(v) => Some(*v as u128),
            Self::U64(v) => Some(*v as u128),
            Self::U128(v) => Some(*v),
            Self::Bool(v) => Some(*v as u128),
            Self::Address(addr) => Some(addr.value()),
            _ => unreachable!(),
        }
    }

    pub fn field_value<F: Field>(&self) -> Option<F> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => Some(F::from_u128(*v as u128)),
            Self::U16(v) => Some(F::from_u128(*v as u128)),
            Self::U32(v) => Some(F::from_u128(*v as u128)),
            Self::U64(v) => Some(F::from_u128(*v as u128)),
            Self::U128(v) => Some(F::from_u128(*v)),
            Self::Bool(v) => Some(F::from_u128(*v as u128)),
            Self::Address(addr) => Some(addr.field_value()),
            _ => unreachable!(),
        }
    }

    pub fn field_value_u256<F: Field>(&self) -> Option<[F; 2]> {
        match self {
            Self::U256(v) => {
                let f = convert_u256_to_u128_pair(v);
                Some([F::from_u128(f[0]), F::from_u128(f[1])])
            }
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
        let value = len as u8;
        Self::U8(value)
    }

    /// Cast the value into simple value if it's simple
    /// NOTICE: restrict access to `pub(self)` so that outside use flatten or flattened_value_len instead of this.
    pub fn cast_simple(&self) -> Option<SimpleValue> {
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

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for Value {}

impl Add for Value {
    type Output = VmResult<Self>;

    fn add(self, b: Value) -> Self::Output {
        let res = match (self, b) {
            (Value::U8(l), Value::U8(r)) => u8::checked_add(l, r).map(Value::U8),
            (Value::U16(l), Value::U16(r)) => u16::checked_add(l, r).map(Value::U16),
            (Value::U32(l), Value::U32(r)) => u32::checked_add(l, r).map(Value::U32),
            (Value::U64(l), Value::U64(r)) => u64::checked_add(l, r).map(Value::U64),
            (Value::U128(l), Value::U128(r)) => u128::checked_add(l, r).map(Value::U128),
            (Value::U256(l), Value::U256(r)) => u256::U256::checked_add(l, r).map(Value::U256),
            (l, r) => {
                let msg = format!("Cannot add {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        };
        res.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
    }
}

impl Sub for Value {
    type Output = VmResult<Self>;

    fn sub(self, b: Value) -> Self::Output {
        let res = match (self, b) {
            (Value::U8(l), Value::U8(r)) => u8::checked_sub(l, r).map(Value::U8),
            (Value::U16(l), Value::U16(r)) => u16::checked_sub(l, r).map(Value::U16),
            (Value::U32(l), Value::U32(r)) => u32::checked_sub(l, r).map(Value::U32),
            (Value::U64(l), Value::U64(r)) => u64::checked_sub(l, r).map(Value::U64),
            (Value::U128(l), Value::U128(r)) => u128::checked_sub(l, r).map(Value::U128),
            (Value::U256(l), Value::U256(r)) => u256::U256::checked_sub(l, r).map(Value::U256),
            (l, r) => {
                let msg = format!("Cannot sub {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        };
        res.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
    }
}

impl Mul for Value {
    type Output = VmResult<Self>;

    fn mul(self, b: Value) -> Self::Output {
        let res = match (self, b) {
            (Value::U8(l), Value::U8(r)) => u8::checked_mul(l, r).map(Value::U8),
            (Value::U16(l), Value::U16(r)) => u16::checked_mul(l, r).map(Value::U16),
            (Value::U32(l), Value::U32(r)) => u32::checked_mul(l, r).map(Value::U32),
            (Value::U64(l), Value::U64(r)) => u64::checked_mul(l, r).map(Value::U64),
            (Value::U128(l), Value::U128(r)) => u128::checked_mul(l, r).map(Value::U128),
            (Value::U256(l), Value::U256(r)) => u256::U256::checked_mul(l, r).map(Value::U256),
            (l, r) => {
                let msg = format!("Cannot mul {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        };
        res.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
    }
}

impl Div for Value {
    type Output = VmResult<Self>;

    fn div(self, b: Value) -> Self::Output {
        let res = match (self, b) {
            (Value::U8(l), Value::U8(r)) => u8::checked_div(l, r).map(Value::U8),
            (Value::U16(l), Value::U16(r)) => u16::checked_div(l, r).map(Value::U16),
            (Value::U32(l), Value::U32(r)) => u32::checked_div(l, r).map(Value::U32),
            (Value::U64(l), Value::U64(r)) => u64::checked_div(l, r).map(Value::U64),
            (Value::U128(l), Value::U128(r)) => u128::checked_div(l, r).map(Value::U128),
            (Value::U256(l), Value::U256(r)) => u256::U256::checked_div(l, r).map(Value::U256),
            (l, r) => {
                let msg = format!("Cannot div {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        };
        res.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
    }
}

impl Rem for Value {
    type Output = VmResult<Self>;

    fn rem(self, b: Value) -> Self::Output {
        let res = match (self, b) {
            (Value::U8(l), Value::U8(r)) => u8::checked_rem(l, r).map(Value::U8),
            (Value::U16(l), Value::U16(r)) => u16::checked_rem(l, r).map(Value::U16),
            (Value::U32(l), Value::U32(r)) => u32::checked_rem(l, r).map(Value::U32),
            (Value::U64(l), Value::U64(r)) => u64::checked_rem(l, r).map(Value::U64),
            (Value::U128(l), Value::U128(r)) => u128::checked_rem(l, r).map(Value::U128),
            (Value::U256(l), Value::U256(r)) => u256::U256::checked_rem(l, r).map(Value::U256),
            (l, r) => {
                let msg = format!("Cannot div {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        };
        res.ok_or_else(|| RuntimeError::new(StatusCode::ArithmeticError))
    }
}

impl Not for Value {
    type Output = VmResult<Self>;

    fn not(self) -> Self::Output {
        Ok(Value::Bool(self.is_zero()))
    }
}

impl Value {
    pub fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => true,
            (Self::U8(v1), Self::U8(v2)) => *v1 == *v2,
            (Self::U16(v1), Self::U16(v2)) => *v1 == *v2,
            (Self::U32(v1), Self::U32(v2)) => *v1 == *v2,
            (Self::U64(v1), Self::U64(v2)) => *v1 == *v2,
            (Self::U128(v1), Self::U128(v2)) => *v1 == *v2,
            (Self::U256(v1), Self::U256(v2)) => *v1 == *v2,
            (Self::Bool(v1), Self::Bool(v2)) => *v1 == *v2,
            (Self::Address(a1), Self::Address(a2)) => a1.value() == a2.value(),
            (Self::Container(c1), Self::Container(c2)) => c1.equals(c2),
            (Self::GlobalRef(r1), Self::GlobalRef(r2)) => r1.equals(r2),
            (Self::LocalRef(r1), Self::LocalRef(r2)) => r1.equals(r2),
            (Self::IndexedRef(r1), Self::IndexedRef(r2)) => r1.equals(r2),
            _ => false,
        }
    }

    pub fn less_than(&self, other: &Self) -> VmResult<bool> {
        Ok(match (self, other) {
            (Value::U8(l), Value::U8(r)) => l < r,
            (Value::U16(l), Value::U16(r)) => l < r,
            (Value::U32(l), Value::U32(r)) => l < r,
            (Value::U64(l), Value::U64(r)) => l < r,
            (Value::U128(l), Value::U128(r)) => l < r,
            (Value::U256(l), Value::U256(r)) => l < r,
            (l, r) => {
                let msg = format!(
                    "Cannot compare {:?} and {:?}: incompatible integer types",
                    l, r
                );
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        })
    }

    pub fn less_equal(&self, other: &Self) -> VmResult<bool> {
        Ok(match (self, other) {
            (Value::U8(l), Value::U8(r)) => l <= r,
            (Value::U16(l), Value::U16(r)) => l <= r,
            (Value::U32(l), Value::U32(r)) => l <= r,
            (Value::U64(l), Value::U64(r)) => l <= r,
            (Value::U128(l), Value::U128(r)) => l <= r,
            (Value::U256(l), Value::U256(r)) => l <= r,
            (l, r) => {
                let msg = format!(
                    "Cannot compare {:?} and {:?}: incompatible integer types",
                    l, r
                );
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        })
    }

    pub fn greater_than(&self, other: &Self) -> VmResult<bool> {
        Ok(match (self, other) {
            (Value::U8(l), Value::U8(r)) => l > r,
            (Value::U16(l), Value::U16(r)) => l > r,
            (Value::U32(l), Value::U32(r)) => l > r,
            (Value::U64(l), Value::U64(r)) => l > r,
            (Value::U128(l), Value::U128(r)) => l > r,
            (Value::U256(l), Value::U256(r)) => l > r,
            (l, r) => {
                let msg = format!(
                    "Cannot compare {:?} and {:?}: incompatible integer types",
                    l, r
                );
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        })
    }

    pub fn greater_equal(&self, other: &Self) -> VmResult<bool> {
        Ok(match (self, other) {
            (Value::U8(l), Value::U8(r)) => l >= r,
            (Value::U16(l), Value::U16(r)) => l >= r,
            (Value::U32(l), Value::U32(r)) => l >= r,
            (Value::U64(l), Value::U64(r)) => l >= r,
            (Value::U128(l), Value::U128(r)) => l >= r,
            (Value::U256(l), Value::U256(r)) => l >= r,
            (l, r) => {
                let msg = format!(
                    "Cannot compare {:?} and {:?}: incompatible integer types",
                    l, r
                );
                return Err(RuntimeError::new(StatusCode::InvalidValue).with_message(msg));
            }
        })
    }

    pub fn is_zero(&self) -> bool {
        if let Value::U256(_) = self {
            match u256::U256::try_from(self).ok() {
                Some(v) => v == u256::U256::zero(),
                None => false,
            }
        } else {
            match self.to_u128() {
                Some(v) => v == 0u128,
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
            Self::U16(val) => {
                if val > (std::u8::MAX as u16) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u16({}) to u8", val)))
                } else {
                    Ok(Value::u8(val as u8))
                }
            }
            Self::U32(val) => {
                if val > (std::u8::MAX as u32) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u32({}) to u8", val)))
                } else {
                    Ok(Value::u8(val as u8))
                }
            }
            Self::U64(val) => {
                if val > (std::u8::MAX as u64) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u8", val)))
                } else {
                    Ok(Value::u8(val as u8))
                }
            }
            Self::U128(val) => {
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u8", val)))
                } else {
                    Ok(Value::u8(val as u8))
                }
            }
            Self::U256(_) => {
                let val = u256::U256::try_from(&self).unwrap();
                if val > u256::U256::from(std::u8::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u8", val)))
                } else {
                    Ok(Value::u8(val.unchecked_as_u8()))
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
            Self::U8(val) => Ok(Value::u16(val as u16)),
            Self::U16(_) => Ok(self),
            Self::U32(val) => {
                if val > (std::u16::MAX as u32) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u32({}) to u16", val)))
                } else {
                    Ok(Value::u16(val as u16))
                }
            }
            Self::U64(val) => {
                if val > (std::u16::MAX as u64) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u16", val)))
                } else {
                    Ok(Value::u16(val as u16))
                }
            }
            Self::U128(val) => {
                if val > (std::u16::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u16", val)))
                } else {
                    Ok(Value::u16(val as u16))
                }
            }
            Self::U256(val) => {
                if val > u256::U256::from(std::u16::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u16", val)))
                } else {
                    Ok(Value::u16(val.unchecked_as_u16()))
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
            Self::U8(val) => Ok(Value::u32(val as u32)),
            Self::U16(val) => Ok(Value::u32(val as u32)),
            Self::U32(_) => Ok(self),
            Self::U64(val) => {
                if val > (std::u32::MAX as u64) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u32", val)))
                } else {
                    Ok(Value::u32(val as u32))
                }
            }
            Self::U128(val) => {
                if val > (std::u32::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u32", val)))
                } else {
                    Ok(Value::u32(val as u32))
                }
            }
            Self::U256(val) => {
                if val > u256::U256::from(std::u32::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u32", val)))
                } else {
                    Ok(Value::u32(val.unchecked_as_u32()))
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
            Self::U8(val) => Ok(Value::u64(val as u64)),
            Self::U16(val) => Ok(Value::u64(val as u64)),
            Self::U32(val) => Ok(Value::u64(val as u64)),
            Self::U64(_) => Ok(self),
            Self::U128(val) => {
                if val > (std::u64::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u64", val)))
                } else {
                    Ok(Value::u64(val as u64))
                }
            }
            Self::U256(val) => {
                if val > u256::U256::from(std::u64::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u64", val)))
                } else {
                    Ok(Value::u64(val.unchecked_as_u64()))
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
            Self::U8(val) => Ok(Value::u128(val as u128)),
            Self::U16(val) => Ok(Value::u128(val as u128)),
            Self::U32(val) => Ok(Value::u128(val as u128)),
            Self::U64(val) => Ok(Value::u128(val as u128)),
            Self::U128(_) => Ok(self),
            Self::U256(val) => {
                if val > u256::U256::from(std::u128::MAX) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u256({}) to u128", val)))
                } else {
                    Ok(Value::u128(val.unchecked_as_u128()))
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
            Self::U8(val) => {
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U16(val) => {
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U32(val) => {
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U64(val) => {
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U128(val) => {
                let x = u256::U256::from(val);
                Ok(Self::u256(x))
            }
            Self::U256(_) => Ok(self),
            _ => unreachable!(),
        }
    }

    pub fn eq(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(a.equals(&b)))
    }

    pub fn neq(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(!a.equals(&b)))
    }

    pub fn lt(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(a.less_than(&b)?))
    }

    pub fn le(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(a.less_equal(&b)?))
    }

    pub fn gt(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(a.greater_than(&b)?))
    }

    pub fn ge(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(a.greater_equal(&b)?))
    }

    pub fn shift_checked(v: Value, n_bits: u8, shift_left: bool) -> VmResult<Value> {
        let bytes = Self::num_of_bytes(v.ty()).to_u128().unwrap() as u8;
        let max_bits = bytes * 8 - 1;
        if n_bits > max_bits {
            return Err(RuntimeError::new(StatusCode::ArithmeticError)
                .with_message("exceed max shift bits".to_string()));
        }

        Ok(match v {
            Value::U8(x) => {
                if shift_left {
                    Value::U8(x << n_bits)
                } else {
                    Value::U8(x >> n_bits)
                }
            }
            Value::U16(x) => {
                if shift_left {
                    Value::U16(x << n_bits)
                } else {
                    Value::U16(x >> n_bits)
                }
            }
            Value::U32(x) => {
                if shift_left {
                    Value::U32(x << n_bits)
                } else {
                    Value::U32(x >> n_bits)
                }
            }
            Value::U64(x) => {
                if shift_left {
                    Value::U64(x << n_bits)
                } else {
                    Value::U64(x >> n_bits)
                }
            }
            Value::U128(x) => {
                if shift_left {
                    Value::U128(x << n_bits)
                } else {
                    Value::U128(x >> n_bits)
                }
            }
            Value::U256(x) => {
                if shift_left {
                    Value::U256(x << n_bits)
                } else {
                    Value::U256(x >> n_bits)
                }
            }
            _ => {
                let msg = format!("invalid type {:?}", v);
                return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
            }
        })
    }

    pub fn shl_checked(a: Value, b: Value) -> VmResult<Value> {
        let n_bits = b.to_u128().unwrap() as u8;
        Self::shift_checked(a, n_bits, true)
    }
    pub fn shr_checked(a: Value, b: Value) -> VmResult<Value> {
        let n_bits = b.to_u128().unwrap() as u8;
        Self::shift_checked(a, n_bits, false)
    }

    pub fn bit_and(a: Value, b: Value) -> VmResult<Value> {
        Ok(match (a, b) {
            (Value::U8(l), Value::U8(r)) => Value::U8(l & r),
            (Value::U16(l), Value::U16(r)) => Value::U16(l & r),
            (Value::U32(l), Value::U32(r)) => Value::U32(l & r),
            (Value::U64(l), Value::U64(r)) => Value::U64(l & r),
            (Value::U128(l), Value::U128(r)) => Value::U128(l & r),
            (Value::U256(l), Value::U256(r)) => Value::U256(l & r),
            (l, r) => {
                let msg = format!("Cannot bit_and {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
            }
        })
    }

    pub fn bit_or(a: Value, b: Value) -> VmResult<Value> {
        Ok(match (a, b) {
            (Value::U8(l), Value::U8(r)) => Value::U8(l | r),
            (Value::U16(l), Value::U16(r)) => Value::U16(l | r),
            (Value::U32(l), Value::U32(r)) => Value::U32(l | r),
            (Value::U64(l), Value::U64(r)) => Value::U64(l | r),
            (Value::U128(l), Value::U128(r)) => Value::U128(l | r),
            (Value::U256(l), Value::U256(r)) => Value::U256(l | r),
            (l, r) => {
                let msg = format!("Cannot bit_or {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
            }
        })
    }

    pub fn xor(a: Value, b: Value) -> VmResult<Value> {
        Ok(match (a, b) {
            (Value::U8(l), Value::U8(r)) => Value::U8(l ^ r),
            (Value::U16(l), Value::U16(r)) => Value::U16(l ^ r),
            (Value::U32(l), Value::U32(r)) => Value::U32(l ^ r),
            (Value::U64(l), Value::U64(r)) => Value::U64(l ^ r),
            (Value::U128(l), Value::U128(r)) => Value::U128(l ^ r),
            (Value::U256(l), Value::U256(r)) => Value::U256(l ^ r),
            (l, r) => {
                let msg = format!("Cannot xor {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
            }
        })
    }

    pub fn and(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(!a.is_zero() && !b.is_zero()))
    }

    pub fn or(a: Value, b: Value) -> VmResult<Value> {
        Ok(Value::Bool(!a.is_zero() || !b.is_zero()))
    }

    pub fn diff(a: Value, b: Value) -> VmResult<Value> {
        Ok(match (a, b) {
            (Value::U8(l), Value::U8(r)) => Value::U8(u8::wrapping_sub(l, r)),
            (Value::U16(l), Value::U16(r)) => Value::U16(u16::wrapping_sub(l, r)),
            (Value::U32(l), Value::U32(r)) => Value::U32(u32::wrapping_sub(l, r)),
            (Value::U64(l), Value::U64(r)) => Value::U64(u64::wrapping_sub(l, r)),
            (Value::U128(l), Value::U128(r)) => Value::U128(u128::wrapping_sub(l, r)),
            (Value::U256(l), Value::U256(r)) => Value::U256(u256::U256::wrapping_sub(l, r)),
            (l, r) => {
                let msg = format!("Cannot diff {:?} and {:?}", l, r);
                return Err(RuntimeError::new(StatusCode::TypeMismatch).with_message(msg));
            }
        })
    }
}

impl TryFrom<&SimpleValue> for u8 {
    type Error = RuntimeError;

    fn try_from(value: &SimpleValue) -> VmResult<u8> {
        match value {
            SimpleValue::U8(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl TryFrom<&SimpleValue> for u16 {
    type Error = RuntimeError;

    fn try_from(value: &SimpleValue) -> VmResult<u16> {
        match value {
            SimpleValue::U16(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl TryFrom<&SimpleValue> for u32 {
    type Error = RuntimeError;

    fn try_from(value: &SimpleValue) -> VmResult<u32> {
        match value {
            SimpleValue::U32(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl TryFrom<&SimpleValue> for u64 {
    type Error = RuntimeError;

    fn try_from(value: &SimpleValue) -> VmResult<u64> {
        match value {
            SimpleValue::U64(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl TryFrom<&SimpleValue> for u128 {
    type Error = RuntimeError;

    fn try_from(value: &SimpleValue) -> VmResult<u128> {
        match value {
            SimpleValue::U128(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u8 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u8> {
        match value {
            Value::U8(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u16 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u16> {
        match value {
            Value::U16(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u32 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u32> {
        match value {
            Value::U32(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u64 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u64> {
        match value {
            Value::U64(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u128 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u128> {
        match value {
            Value::U128(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for u256::U256 {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<u256::U256> {
        match value {
            Value::U256(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
impl TryFrom<&Value> for bool {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<bool> {
        match value {
            Value::Bool(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl TryFrom<&Value> for AccountAddress {
    type Error = RuntimeError;

    fn try_from(value: &Value) -> VmResult<AccountAddress> {
        match value {
            Value::Address(v) => Ok(*v),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}

impl From<Value> for Option<MoveValue> {
    fn from(value: Value) -> Option<MoveValue> {
        value.cast_simple().map(Into::into)
    }
}

impl<F: Field> From<Value> for CircuitValue<F> {
    fn from(value: Value) -> CircuitValue<F> {
        match value.field_value() {
            Some(v) => CircuitValue::known(v),
            None => CircuitValue::unknown(),
        }
    }
}

impl Value {
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

impl Container {
    pub fn copy_value(&self) -> Self {
        Self(Rc::new(RefCell::new(
            self.0.borrow().iter().map(|v| v.copy_value()).collect(),
        )))
    }
}

impl Value {
    pub fn into_account_address(self) -> VmResult<AccountAddress> {
        match self {
            Value::Address(address) => Ok(address),
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as AccountAddress".to_string())),
        }
    }
}

#[derive(Debug)]
pub struct ContainerValue(Vec<Value>);

impl ContainerValue {
    pub fn pack(values: Vec<Value>) -> Self {
        Self(values)
    }

    pub fn unpack(self) -> Vec<Value> {
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
pub enum GlobalValue {
    /// No resource resides in this slot or in storage.
    None,
    /// A resource has been published to this slot and it did not previously exist in storage.
    Fresh { fields: Rc<RefCell<Vec<Value>>> },
    /// A resource resides in this slot and also in storage. The status flag indicates whether
    /// it has potentially been altered.
    Cached {
        fields: Rc<RefCell<Vec<Value>>>,
        status: Rc<RefCell<GlobalDataStatus>>,
    },
    /// A resource used to exist in storage but has been deleted by the current transaction.
    Deleted,
}

impl GlobalValue {
    pub fn none() -> Self {
        GlobalValue::None
    }

    fn fresh(val: Value) -> VmResult<Self> {
        match val {
            Value::Container(Container(fields)) => Ok(Self::Fresh { fields }),
            _ => Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("not a resource type".to_string()),
            ),
        }
    }

    fn cached(val: Value, status: GlobalDataStatus) -> VmResult<Self> {
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

    pub fn move_from(&mut self) -> VmResult<Value> {
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

    pub fn move_to(&mut self, val: Value) -> VmResult<()> {
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
        address: AccountAddress,
        sd_index: GlobalResourceDefIndex,
    ) -> VmResult<GlobalRef> {
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
