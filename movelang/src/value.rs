// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use crate::account_address::AccountAddress;
use crate::utility::{convert_to_field, move_div, move_rem};
use crate::utility::{MoveValue, MoveValueType};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Value as CircuitValue;
use move_binary_format::file_format::StructDefinitionIndex;
use std::convert::TryFrom;
use std::ops::{Add, Div, Mul, Not, Rem, Sub};
use std::{cell::RefCell, rc::Rc};

pub const NUM_OF_BYTES_U8: usize = 1;
pub const NUM_OF_BYTES_U64: usize = 8;
pub const NUM_OF_BYTES_U128: usize = 16;

#[derive(Copy, Clone, Debug)]
pub struct U8<F: FieldExt>(F);

#[derive(Copy, Clone, Debug)]
pub struct U64<F: FieldExt>(F);

#[derive(Copy, Clone, Debug)]
pub struct U128<F: FieldExt>(F);

#[derive(Copy, Clone, Debug)]
pub struct Bool<F: FieldExt>(F);

/// A wrapper for account address
#[derive(Copy, Clone, Debug)]
pub struct Address<F: FieldExt>(AccountAddress<F>);

impl<F: FieldExt> Address<F> {
    pub fn account_address(self) -> AccountAddress<F> {
        self.0
    }
    pub fn value(&self) -> F {
        self.0.value()
    }
}

/// Index of a frame
#[derive(Clone, Debug)]
pub struct FrameIndex(pub usize);

/// Index of a value in locals, or index of a member in the struct
#[derive(Clone, Debug)]
pub struct Index(pub usize);

/// An address of a zkMove value
#[derive(Clone, Debug)]
pub enum ValueAddress<F: FieldExt> {
    /// If the value lives in the locals of a frame, the address will be the
    /// combination of frame_index and the index of the value in locals.
    Local(FrameIndex, Index),
    /// If the value lives in the global storage, the address will be the
    /// AccountAddress/StructDefinitionIndex of the value.
    Global(AccountAddress<F>, StructDefinitionIndex),
    /// If the value is a member of a struct, the address will be the
    /// index of the member in the struct.
    Indexed(Index),
    /// The value was just created and has not been stored yet.
    Unknown,
}

#[derive(Debug)]
pub enum Container<F: FieldExt> {
    Locals(FrameIndex, Rc<RefCell<Vec<Value<F>>>>),
    Struct(ValueAddress<F>, Rc<RefCell<Vec<Value<F>>>>),
}

//todo: As a workaround, we temporarily use 0 and 1 to represent the container.
// It should be replaced by a value that truly represents the container.
pub enum FakeContainerValue {
    LOCALS,
    STRUCT,
}

impl<F: FieldExt> Container<F> {
    pub fn len(&self) -> usize {
        match self {
            Self::Locals(_, r) => r.borrow().len(),
            Self::Struct(_, r) => r.borrow().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Locals(_, r) => r.borrow().is_empty(),
            Self::Struct(_, r) => r.borrow().is_empty(),
        }
    }

    pub fn rc_count(&self) -> usize {
        match self {
            Self::Locals(_, r) => Rc::strong_count(r),
            Self::Struct(_, r) => Rc::strong_count(r),
        }
    }

    pub fn value(&self) -> F {
        match self {
            Self::Locals(_, _) => F::from_u128(FakeContainerValue::LOCALS as u128),
            Self::Struct(_, _) => F::from_u128(FakeContainerValue::STRUCT as u128),
        }
    }

    pub fn signer(x: AccountAddress<F>) -> Self {
        Container::Struct(
            ValueAddress::Unknown,
            Rc::new(RefCell::new(vec![Value::Address(Address(x))])),
        )
    }

    pub fn frame_index(&self) -> usize {
        match self {
            Self::Locals(frame_index, _) => frame_index.0,
            Self::Struct(address, _) => match address {
                ValueAddress::Local(frame_index, _index) => frame_index.0,
                _ => unreachable!(),
            },
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::Locals(_, _) => unreachable!(),
            Self::Struct(address, _) => match address {
                ValueAddress::Local(_frame_index, index) => index.0,
                _ => unreachable!(),
            },
        }
    }
}

/// A ContainerRef is a reference to a container, which could live either
/// in the frame or in global storage.
#[derive(Clone, Debug)]
pub enum ContainerRef<F: FieldExt> {
    Local(Container<F>),
    Global(Container<F>),
}

impl<F: FieldExt> ContainerRef<F> {
    fn container(&self) -> &Container<F> {
        match self {
            Self::Local(container) => container,
            Self::Global(container) => container,
        }
    }

    fn read_ref(&self) -> VmResult<Value<F>> {
        Ok(Value::Container(self.container().copy_value()))
    }

    pub fn borrow_element(&self, element_idx: usize) -> VmResult<Value<F>> {
        let res = match self.container() {
            Container::Locals(_, _) => {
                unreachable!("should not come here.")
            }
            Container::Struct(_, r) => {
                let len = r.borrow().len();
                if element_idx >= len {
                    return Err(
                        RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                            "index out of bounds when borrowing container element: index: {}, length: {}",
                            element_idx, len
                        )),
                    );
                }
                let v = r.borrow();
                match &v[element_idx] {
                    Value::Container(container) => {
                        let r = match self {
                            Self::Local(_) => Self::Local(container.copy_by_ref()),
                            Self::Global(_) => unimplemented!(),
                        };
                        Value::ContainerRef(r)
                    }
                    _ => Value::IndexedRef(IndexedRef {
                        index: element_idx,
                        container_ref: self.copy_value(),
                    }),
                }
            }
        };

        Ok(res)
    }

    fn copy_value(&self) -> Self {
        match self {
            Self::Local(container) => Self::Local(container.copy_by_ref()),
            Self::Global(container) => Self::Global(container.copy_by_ref()),
        }
    }

    fn is_global(&self) -> bool {
        matches!(self, Self::Global(_)) // container holds global value
    }

    fn global_path(&self) -> (AccountAddress<F>, &StructDefinitionIndex) {
        match self {
            Self::Local(_) => unreachable!(),
            Self::Global(c) => match c {
                Container::Locals(_, _) => unreachable!(),
                Container::Struct(addr, _) => match addr {
                    ValueAddress::Global(address, sd_index) => (address.copy(), sd_index),
                    _ => unreachable!(),
                },
            },
        }
    }

    fn copy_global_value(&self) -> VmResult<Value<F>> {
        if self.is_global() {
            self.read_ref()
        } else {
            Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("The value doesn't contain global value".to_string()))
        }
    }
}

/// A reference pointing to an element in a container.
#[derive(Clone, Debug)]
pub struct IndexedRef<F: FieldExt> {
    pub index: usize,
    pub container_ref: ContainerRef<F>,
}

impl<F: FieldExt> IndexedRef<F> {
    pub fn container(&self) -> &Container<F> {
        self.container_ref.container()
    }
    pub fn container_ref(&self) -> &ContainerRef<F> {
        &self.container_ref
    }
    fn read_ref(&self) -> VmResult<Value<F>> {
        let value = match &*self.container_ref.container() {
            Container::Locals(_, r) | Container::Struct(_, r) => {
                r.borrow()[self.index].copy_value()
            }
        };
        Ok(value)
    }
    fn write_ref(&mut self, x: Value<F>) -> VmResult<()> {
        match &x {
            Value::IndexedRef(_)
            | Value::ContainerRef(_)
            | Value::Invalid
            | Value::Container(_) => return Err(RuntimeError::new(StatusCode::TypeMismatch)),
            _ => (),
        }

        match (self.container_ref.container(), &x) {
            (Container::Locals(_, r), _) | (Container::Struct(_, r), _) => {
                let mut v = r.borrow_mut();
                v[self.index] = x;
            }
        }
        Ok(())
    }
    pub fn index(&self) -> usize {
        self.index
    }
    fn container_frame_index(&self) -> usize {
        self.container().frame_index()
    }
    fn copy_value(&self) -> Self {
        Self {
            index: self.index,
            container_ref: self.container_ref.copy_value(),
        }
    }
    pub fn borrow_element(&self, element_idx: usize) -> VmResult<Value<F>> {
        let res = match self.container() {
            Container::Locals(_, _) => {
                unreachable!("should not come here.")
            }
            Container::Struct(_, r) => {
                let len = r.borrow().len();
                if element_idx >= len {
                    return Err(
                        RuntimeError::new(StatusCode::OutOfBounds).with_message(format!(
                            "index out of bounds when borrowing container element: index: {}, length: {}",
                            element_idx, len
                        )),
                    );
                }
                let v = r.borrow();
                match &v[element_idx] {
                    Value::Container(container) => {
                        let r = match self.container_ref {
                            ContainerRef::Local(_) => ContainerRef::Local(container.copy_by_ref()),
                            ContainerRef::Global(_) => unreachable!(),
                        };
                        Value::ContainerRef(r)
                    }
                    _ => Value::IndexedRef(IndexedRef {
                        index: self.index,
                        container_ref: self.container_ref.copy_value(),
                    }),
                }
            }
        };

        Ok(res)
    }

    fn is_global(&self) -> bool {
        self.container_ref().is_global()
    }

    fn global_path(&self) -> (AccountAddress<F>, &StructDefinitionIndex) {
        self.container_ref.global_path()
    }

    fn copy_global_value(&self) -> VmResult<Value<F>> {
        if self.is_global() {
            self.container_ref().read_ref()
        } else {
            Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message("The value doesn't contain global value".to_string()))
        }
    }
}

/// A wrapper to support read_ref and write_ref.
#[derive(Debug, Clone)]
pub enum Reference<F: FieldExt> {
    IndexedRef(IndexedRef<F>),
    ContainerRef(ContainerRef<F>),
}

impl<F: FieldExt> Reference<F> {
    pub fn read_ref(&self) -> VmResult<Value<F>> {
        match self {
            Self::ContainerRef(r) => r.read_ref(),
            Self::IndexedRef(r) => r.read_ref(),
        }
    }
    pub fn write_ref(&mut self, x: Value<F>) -> VmResult<()> {
        match self {
            Self::ContainerRef(_) => unimplemented!(),
            Self::IndexedRef(r) => r.write_ref(x),
        }
    }
    pub fn index(&self) -> usize {
        match self {
            Self::ContainerRef(_) => unimplemented!(),
            Self::IndexedRef(r) => r.index(),
        }
    }
    pub fn container_frame_index(&self) -> usize {
        match self {
            Self::ContainerRef(_) => unimplemented!(),
            Self::IndexedRef(r) => r.container_frame_index(),
        }
    }

    pub fn is_global(&self) -> bool {
        match self {
            Self::ContainerRef(r) => r.is_global(),
            Self::IndexedRef(r) => r.is_global(),
        }
    }

    pub fn global_path(&self) -> (AccountAddress<F>, &StructDefinitionIndex) {
        match self {
            Self::ContainerRef(r) => r.global_path(),
            Self::IndexedRef(r) => r.global_path(),
        }
    }

    // For a reference pointing to a global value, return the global value
    // For a reference pointing to an element of a global value, return the global value
    pub fn copy_global_value(&self) -> VmResult<Value<F>> {
        match self {
            Self::ContainerRef(r) => r.copy_global_value(),
            Self::IndexedRef(r) => r.copy_global_value(),
        }
    }
}

/// A wrapper to support borrow_element
#[derive(Debug, Clone)]
pub struct StructRef<F: FieldExt>(pub ContainerRef<F>);

impl<F: FieldExt> StructRef<F> {
    pub fn borrow_element(&self, field_idx: usize) -> VmResult<Value<F>> {
        self.0.borrow_element(field_idx)
    }
}

#[derive(Debug)]
pub struct Struct<F: FieldExt> {
    fields: Vec<Value<F>>,
}

impl<F: FieldExt> Struct<F> {
    pub fn pack(values: Vec<Value<F>>) -> Self {
        Self { fields: values }
    }

    pub fn unpack(self) -> VmResult<Vec<Value<F>>> {
        Ok(self.fields)
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
pub enum GlobalValue<F: FieldExt> {
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

impl<F: FieldExt> GlobalValue<F> {
    pub fn none() -> Self {
        GlobalValue::None
    }

    fn fresh(val: Value<F>) -> VmResult<Self> {
        match val {
            Value::Container(Container::Struct(_address, fields)) => Ok(Self::Fresh { fields }),
            _ => Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("not a resource type".to_string()),
            ),
        }
    }

    fn cached(val: Value<F>, status: GlobalDataStatus) -> VmResult<Self> {
        match val {
            Value::Container(Container::Struct(_address, fields)) => {
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
        Ok(Value::Container(Container::Struct(
            ValueAddress::Unknown,
            fields,
        )))
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
        sd_index: StructDefinitionIndex,
    ) -> VmResult<Value<F>> {
        match self {
            Self::None | Self::Deleted => Err(RuntimeError::new(StatusCode::MissingData)),
            Self::Fresh { fields } => Ok(Value::ContainerRef(ContainerRef::Global(
                Container::Struct(ValueAddress::Global(address, sd_index), Rc::clone(fields)),
            ))),
            Self::Cached { fields, status: _ } => Ok(Value::ContainerRef(ContainerRef::Global(
                Container::Struct(ValueAddress::Global(address, sd_index), Rc::clone(fields)),
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Value<F: FieldExt> {
    Invalid,
    U8(U8<F>),
    U64(U64<F>),
    U128(U128<F>),
    Bool(Bool<F>),
    Address(Address<F>),
    Container(Container<F>),
    ContainerRef(ContainerRef<F>),
    IndexedRef(IndexedRef<F>),
}

impl<F: FieldExt> Value<F> {
    pub fn new(value: F, ty: MoveValueType) -> VmResult<Self> {
        match ty {
            MoveValueType::U8 => Ok(Value::U8(U8(value))),
            MoveValueType::U64 => Ok(Value::U64(U64(value))),
            MoveValueType::U128 => Ok(Value::U128(U128(value))),
            MoveValueType::Bool => Ok(Value::Bool(Bool(value))),
            MoveValueType::Signer => Ok(Value::signer(AccountAddress::new(value))),
            MoveValueType::Address => Ok(Value::address(AccountAddress::new(value))),
            _ => unimplemented!(),
        }
    }
    pub fn bool(x: bool) -> Self {
        let value = if x { F::one() } else { F::zero() };
        Self::Bool(Bool(value))
    }
    pub fn u8(x: u8) -> Self {
        let value = F::from_u128(x as u128);
        Self::U8(U8(value))
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
        Self::Address(Address(x))
    }

    pub fn signer(x: AccountAddress<F>) -> Self {
        Self::Container(Container::signer(x))
    }

    pub fn struct_(s: Struct<F>, address: ValueAddress<F>) -> Self {
        Self::Container(Container::Struct(address, Rc::new(RefCell::new(s.fields))))
    }

    /// The address of an value may be unknown at the moment when the value is created.
    /// Can be filled by calling this function when the address is known.
    pub fn fill_address_if_needed(self, address: ValueAddress<F>) -> Value<F> {
        match self {
            // only struct container need filling address
            Value::Container(Container::Struct(ValueAddress::Unknown, struct_)) => {
                Value::Container(Container::Struct(address, struct_))
            }
            v => v,
        }
    }

    pub fn value(&self) -> Option<F> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => Some(v.0),
            Self::U64(v) => Some(v.0),
            Self::U128(v) => Some(v.0),
            Self::Bool(v) => Some(v.0),
            Self::Address(addr) => Some(addr.value()),
            Self::Container(c) => Some(c.value()),
            Self::IndexedRef(r) => Some(r.container().value()),
            Self::ContainerRef(r) => Some(r.container().value()),
        }
    }

    pub fn ty(&self) -> MoveValueType {
        match self {
            Self::Invalid => {
                unreachable!()
            }
            Self::U8(_) => MoveValueType::U8,
            Self::U64(_) => MoveValueType::U64,
            Self::U128(_) => MoveValueType::U128,
            Self::Bool(_) => MoveValueType::Bool,
            _ => unimplemented!(),
        }
    }

    pub fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Invalid, Self::Invalid) => true,
            (Self::U8(v1), Self::U8(v2)) => v1.0 == v2.0,
            (Self::U64(v1), Self::U64(v2)) => v1.0 == v2.0,
            (Self::U128(v1), Self::U128(v2)) => v1.0 == v2.0,
            (Self::Bool(v1), Self::Bool(v2)) => v1.0 == v2.0,
            _ => false,
        }
    }

    pub fn less_than(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 < v2),
            _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
        }
    }

    pub fn less_equal(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 <= v2),
            _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
        }
    }

    pub fn greater_than(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 > v2),
            _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
        }
    }

    pub fn greater_equal(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 >= v2),
            _ => Err(RuntimeError::new(StatusCode::InvalidValue)),
        }
    }

    pub fn is_zero(&self) -> bool {
        match self.value() {
            Some(v) => v.is_zero_vartime(),
            None => false,
        }
    }

    pub fn is_integer(&self) -> bool {
        matches!(self, Self::U8(_) | Self::U64(_) | Self::U128(_))
    }

    pub fn castu8(self) -> VmResult<Self> {
        if !self.is_integer() {
            return Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as u8".to_string()));
        }
        let val = self.value().unwrap().get_lower_128();

        match self {
            Self::U8(_) => Ok(self),
            Self::U64(_) => {
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u64({}) to u8", val)))
                } else {
                    // Self::u64(val as u64, None)
                    Value::new(F::from_u128(val), MoveValueType::U8)
                }
            }
            Self::U128(_) => {
                if val > (std::u8::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u8", val)))
                } else {
                    // Self::u128(val, None)
                    Value::new(F::from_u128(val), MoveValueType::U8)
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
        let val = self.value().unwrap().get_lower_128();

        match self {
            Self::U8(_) | Self::U64(_) => Value::new(F::from_u128(val), MoveValueType::U64),
            Self::U128(_) => {
                if val > (std::u64::MAX as u128) {
                    Err(RuntimeError::new(StatusCode::ArithmeticError)
                        .with_message(format!("Cannot cast u128({}) to u64", val)))
                } else {
                    // Self::u128(val, None)
                    Value::new(F::from_u128(val), MoveValueType::U64)
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
        let val = self.value().unwrap().get_lower_128();

        match self {
            Self::U8(_) | Self::U64(_) | Self::U128(_) => {
                Value::new(F::from_u128(val), MoveValueType::U128)
            }
            _ => unreachable!(),
        }
    }

    pub fn div_rem(&self, other: Value<F>) -> VmResult<(Value<F>, Value<F>)> {
        let l_move: Option<MoveValue> = self.clone().into();
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

impl<F: FieldExt> PartialEq for Value<F> {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl<F: FieldExt> Eq for Value<F> {}

impl<F: FieldExt> Add for Value<F> {
    type Output = VmResult<Self>;

    fn add(self, b: Value<F>) -> Self::Output {
        // implement add based on checked_add API to check arithmetic overflow
        // let value = self.value().and_then(|a| b.value().map(|b| a + b));
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                u8::checked_add(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            ),
            (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                u64::checked_add(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
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

impl<F: FieldExt> Sub for Value<F> {
    type Output = VmResult<Self>;

    fn sub(self, b: Value<F>) -> Self::Output {
        // implement sub based on checked_sub API to check arithmetic overflow
        // let value = self.value().and_then(|a| b.value().map(|b| a - b));
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                u8::checked_sub(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            ),
            (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                u64::checked_sub(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
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

impl<F: FieldExt> Mul for Value<F> {
    type Output = VmResult<Self>;

    fn mul(self, b: Value<F>) -> Self::Output {
        // implement mul based on checked_mul API to check arithmetic overflow
        // let value = self.value().and_then(|a| b.value().map(|b| a * b));
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => F::from_u128(
                u8::checked_mul(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            ),
            (MoveValueType::U64, MoveValueType::U64) => F::from_u128(
                u64::checked_mul(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
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

impl<F: FieldExt> Div for Value<F> {
    type Output = VmResult<Self>;

    fn div(self, b: Value<F>) -> Self::Output {
        let l_move: Option<MoveValue> = self.clone().into();
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

impl<F: FieldExt> Rem for Value<F> {
    type Output = VmResult<Self>;

    fn rem(self, b: Value<F>) -> Self::Output {
        let l_move: Option<MoveValue> = self.clone().into();
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

impl<F: FieldExt> Not for Value<F> {
    type Output = VmResult<Self>;

    fn not(self) -> Self::Output {
        let value = if self.is_zero() { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }
}

impl<F: FieldExt> Value<F> {
    pub fn eq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = match (a.value(), b.value()) {
            (Some(a), Some(b)) => {
                if a == b {
                    F::one()
                } else {
                    F::zero()
                }
            }
            _ => F::zero(),
        };

        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn neq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if !a.equals(&b) { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn lt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lt = a.less_than(&b)?;
        let value = if lt { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn le(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let le = a.less_equal(&b)?;
        let value = if le { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn gt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let gt = a.greater_than(&b)?;
        let value = if gt { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn ge(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let ge = a.greater_equal(&b)?;
        let value = if ge { F::one() } else { F::zero() };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn bit_and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        // Bitwise AND the 2 u64
        if a.ty() != MoveValueType::U64 || b.ty() != MoveValueType::U64 {
            return Err(RuntimeError::new(StatusCode::UnsupportedMoveType)
                .with_message("the value should be u64".to_string()));
        }
        let lhs = a.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = F::from_u128(lhs & rhs);
        let value = Value::new(value, a.ty())?;
        Ok(value)
    }

    pub fn bit_or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        // Bitwise OR the 2 u64
        if a.ty() != MoveValueType::U64 || b.ty() != MoveValueType::U64 {
            return Err(RuntimeError::new(StatusCode::UnsupportedMoveType)
                .with_message("the value should be u64".to_string()));
        }
        let lhs = a.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = F::from_u128(lhs | rhs);
        let value = Value::new(value, a.ty())?;
        Ok(value)
    }

    pub fn xor(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        // Bitwise XOR the 2 u64
        if a.ty() != MoveValueType::U64 || b.ty() != MoveValueType::U64 {
            return Err(RuntimeError::new(StatusCode::UnsupportedMoveType)
                .with_message("the value should be u64".to_string()));
        }
        let lhs = a.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = F::from_u128(lhs ^ rhs);
        let value = Value::new(value, a.ty())?;
        Ok(value)
    }

    pub fn and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() || b.is_zero() {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() && b.is_zero() {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new(value, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn delta_invert(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let delta_invert = if a.value() == b.value() {
            F::one()
        } else {
            let delta = a.value().unwrap() - b.value().unwrap();
            delta.invert().unwrap()
        };

        let value = Value::new(delta_invert, a.ty())?;
        Ok(value)
    }

    pub fn diff(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lhs = a.value().unwrap();
        let rhs = b.value().unwrap();
        let range = F::from(2).pow(&[(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);
        let range_or_zero = if lhs < rhs { range } else { F::zero() };
        let diff = (lhs - rhs) + range_or_zero;
        let value = Value::new(diff, a.ty())?;
        Ok(value)
    }
}

impl<F: FieldExt> From<Value<F>> for Option<MoveValue> {
    fn from(value: Value<F>) -> Option<MoveValue> {
        match value.value() {
            Some(field) => {
                let value = match value.ty() {
                    MoveValueType::U8 => MoveValue::U8(field.get_lower_128() as u8),
                    MoveValueType::U64 => MoveValue::U64(field.get_lower_128() as u64),
                    MoveValueType::U128 => MoveValue::U128(field.get_lower_128()),
                    MoveValueType::Bool => MoveValue::Bool(field == F::one()),
                    _ => unimplemented!(),
                };
                Some(value)
            }
            None => None,
        }
    }
}

impl<F: FieldExt> From<Value<F>> for CircuitValue<F> {
    fn from(value: Value<F>) -> CircuitValue<F> {
        match value.value() {
            Some(v) => CircuitValue::known(v),
            None => CircuitValue::unknown(),
        }
    }
}

impl<F: FieldExt> Value<F> {
    /// We have two methods to "copy" a value - copy_value() and clone(). copy_value() is
    /// a "shallow" copy, only the stack data is copied; clone() is a "deep" copy, not only
    /// the stack data but also the referenced data in locals is copied.
    ///
    /// For example, copy_value() of ContainerRef returns a ref pointing to the original
    /// container, but clone() of ContainerRef returns a ref pointing to a copied container.
    pub fn copy_value(&self) -> Self {
        match self {
            Self::Invalid => Self::Invalid,
            Self::U8(v) => Self::U8(*v),
            Self::U64(v) => Self::U64(*v),
            Self::U128(v) => Self::U128(*v),
            Self::Bool(v) => Self::Bool(*v),
            Self::Address(addr) => Self::Address(*addr),
            Self::Container(c) => Self::Container(c.copy_value()),
            Self::ContainerRef(r) => Self::ContainerRef(r.copy_value()),
            Self::IndexedRef(r) => Self::IndexedRef(r.copy_value()),
        }
    }
}
impl<F: FieldExt> Container<F> {
    /// A "shallow" copy, only the stack data is copied.
    pub fn copy_value(&self) -> Self {
        match self {
            Self::Struct(address, r) => {
                let struct_ = Rc::new(RefCell::new(
                    r.borrow().iter().map(|v| v.copy_value()).collect(),
                ));
                Self::Struct(address.clone(), struct_)
            }
            // locals is copied by ref
            Self::Locals(frame_index, l) => Self::Locals(frame_index.clone(), Rc::clone(l)),
        }
    }

    pub fn copy_by_ref(&self) -> Self {
        match self {
            Self::Struct(address, r) => Self::Struct(address.clone(), Rc::clone(r)),
            Self::Locals(frame_index, r) => Self::Locals(frame_index.clone(), Rc::clone(r)),
        }
    }
}

impl<F: FieldExt> Clone for Container<F> {
    /// A "deep" copy, not only the stack data but also the referenced data in locals is copied.
    fn clone(&self) -> Self {
        match self {
            Self::Struct(address, r) => {
                let struct_ = Rc::new(RefCell::new(
                    r.borrow().iter().map(|v| v.copy_value()).collect(),
                ));
                Self::Struct(address.clone(), struct_)
            }
            Self::Locals(frame_index, l) => {
                let locals = Rc::new(RefCell::new(
                    l.borrow().iter().map(|v| v.copy_value()).collect(),
                ));
                Self::Locals(frame_index.clone(), locals)
            }
        }
    }
}

impl<F: FieldExt> Value<F> {
    pub fn as_account_address(self) -> VmResult<AccountAddress<F>> {
        match self {
            Value::Address(address) => Ok(address.account_address()),
            _ => Err(RuntimeError::new(StatusCode::ValueConversionError)
                .with_message("the value can not be cast as AccountAddress".to_string())),
        }
    }

    pub fn as_reference(self) -> VmResult<Reference<F>> {
        match self {
            Value::ContainerRef(r) => Ok(Reference::ContainerRef(r)),
            Value::IndexedRef(r) => Ok(Reference::IndexedRef(r)),
            v => Err(RuntimeError::new(StatusCode::TypeMismatch)
                .with_message(format!("cannot convert {:?} to reference", v))),
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub enum IntegerType {
    U8,
    U64,
    U128,
}

impl IntegerType {
    pub fn num_of_bytes(&self) -> usize {
        match self {
            Self::U8 => NUM_OF_BYTES_U8,
            Self::U64 => NUM_OF_BYTES_U64,
            Self::U128 => NUM_OF_BYTES_U128,
        }
    }
}

impl TryFrom<MoveValueType> for IntegerType {
    type Error = RuntimeError;

    fn try_from(move_ty: MoveValueType) -> VmResult<IntegerType> {
        match move_ty {
            MoveValueType::U8 => Ok(IntegerType::U8),
            MoveValueType::U64 => Ok(IntegerType::U64),
            MoveValueType::U128 => Ok(IntegerType::U128),
            _ => Err(RuntimeError::new(StatusCode::TypeMismatch)),
        }
    }
}
