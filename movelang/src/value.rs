// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use crate::account_address::AccountAddress;
use crate::utility::{convert_to_field, move_div, move_rem};
use crate::utility::{MoveValue, MoveValueType};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::{arithmetic::FieldExt, circuit::Cell};
use std::ops::{Add, Div, Mul, Not, Rem, Sub};
use std::{cell::RefCell, rc::Rc};

pub const NUM_OF_BYTES_U128: usize = 16;

#[derive(Clone, Debug)]
pub struct U8<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug)]
pub struct U64<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug)]
pub struct U128<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug)]
pub struct Bool<F: FieldExt> {
    pub value: Option<F>,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug)]
pub struct Address<F: FieldExt> {
    pub account_address: Option<AccountAddress<F>>,
    pub cell: Option<Cell>,
}

impl<F: FieldExt> Address<F> {
    pub fn account_address(self) -> AccountAddress<F> {
        self.account_address.expect("address should not be None")
    }
    pub fn value(&self) -> Option<F> {
        self.account_address.map(|addr| addr.value())
    }
}

#[derive(Debug)]
pub enum Container<F: FieldExt> {
    Locals(Rc<RefCell<Vec<Value<F>>>>),
    Struct(Rc<RefCell<Vec<Value<F>>>>),
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
            Self::Locals(r) => r.borrow().len(),
            Self::Struct(r) => r.borrow().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Locals(r) => r.borrow().is_empty(),
            Self::Struct(r) => r.borrow().is_empty(),
        }
    }

    pub fn rc_count(&self) -> usize {
        match self {
            Self::Locals(r) => Rc::strong_count(r),
            Self::Struct(r) => Rc::strong_count(r),
        }
    }

    pub fn value(&self) -> Option<F> {
        match self {
            Self::Locals(_r) => Some(F::from_u128(FakeContainerValue::LOCALS as u128)),
            Self::Struct(_r) => Some(F::from_u128(FakeContainerValue::STRUCT as u128)),
        }
    }

    pub fn signer(x: AccountAddress<F>) -> Self {
        Container::Struct(Rc::new(RefCell::new(vec![Value::Address(Address {
            account_address: Some(x),
            cell: None,
        })])))
    }
}

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
        Ok(Value::Container(self.container().copy_value()?))
    }

    fn borrow_global_value_element(&self, element_idx: usize) -> VmResult<Value<F>> {
        let res = match self.container() {
            Container::Locals(_) => {
                unreachable!("should not come here.")
            }
            Container::Struct(r) => {
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
                    _ => Value::IndexedRef(IndexedRef::IndexedGlobalRef(IndexedGlobalRef {
                        element_idx,
                        container_ref: self.copy_value(),
                    })),
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
}

// Reference to one of locals
#[derive(Clone, Debug)]
pub struct IndexedLocalsRef<F: FieldExt> {
    pub call_index: usize,
    pub idx: usize,
    pub container_ref: ContainerRef<F>,
}

impl<F: FieldExt> IndexedLocalsRef<F> {
    pub fn container(&self) -> &Container<F> {
        self.container_ref.container()
    }
    pub fn container_ref(self) -> ContainerRef<F> {
        self.container_ref
    }
    fn read_ref(&self) -> VmResult<Value<F>> {
        let value = match &*self.container_ref.container() {
            Container::Locals(r) | Container::Struct(r) => r.borrow()[self.idx].copy_value()?,
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
            (Container::Locals(r), _) | (Container::Struct(r), _) => {
                let mut v = r.borrow_mut();
                v[self.idx] = x;
            }
        }
        Ok(())
    }
    fn index(&self) -> usize {
        self.idx
    }
    fn call_index(&self) -> usize {
        self.call_index
    }
    fn copy_value(&self) -> Self {
        Self {
            call_index: self.call_index,
            idx: self.idx,
            container_ref: self.container_ref.copy_value(),
        }
    }
    pub fn borrow_element(&self, element_idx: usize) -> VmResult<Value<F>> {
        let res = match self.container() {
            Container::Locals(_) => {
                unreachable!("should not come here.")
            }
            Container::Struct(r) => {
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
                    _ => Value::IndexedRef(IndexedRef::IndexedStructRef(IndexedStructRef {
                        call_index: self.call_index,
                        idx: self.idx,
                        element_idx,
                        container_ref: self.container_ref.copy_value(),
                    })),
                }
            }
        };

        Ok(res)
    }
}

// Reference to an element of a struct
#[derive(Clone, Debug)]
pub struct IndexedStructRef<F: FieldExt> {
    pub call_index: usize,
    pub idx: usize,
    pub element_idx: usize,
    pub container_ref: ContainerRef<F>,
}

impl<F: FieldExt> IndexedStructRef<F> {
    pub fn container(&self) -> &Container<F> {
        self.container_ref.container()
    }
    pub fn container_ref(self) -> ContainerRef<F> {
        self.container_ref
    }
    fn read_ref(&self) -> VmResult<Value<F>> {
        let value = match &*self.container_ref.container() {
            Container::Locals(r) => r.borrow()[self.idx].copy_value()?,
            Container::Struct(r) => r.borrow()[self.element_idx].copy_value()?,
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
            (Container::Locals(r), _) => {
                let mut v = r.borrow_mut();
                v[self.idx] = x;
            }
            (Container::Struct(r), _) => {
                let mut v = r.borrow_mut();
                v[self.element_idx] = x;
            }
        }
        Ok(())
    }
    fn index(&self) -> usize {
        self.idx
    }
    fn call_index(&self) -> usize {
        self.call_index
    }
    fn copy_value(&self) -> Self {
        Self {
            call_index: self.call_index,
            idx: self.idx,
            element_idx: self.element_idx,
            container_ref: self.container_ref.copy_value(),
        }
    }
}

// Reference to an element of a global value
#[derive(Clone, Debug)]
pub struct IndexedGlobalRef<F: FieldExt> {
    pub element_idx: usize,
    pub container_ref: ContainerRef<F>,
}

impl<F: FieldExt> IndexedGlobalRef<F> {
    pub fn container(&self) -> &Container<F> {
        self.container_ref.container()
    }
    pub fn container_ref(self) -> ContainerRef<F> {
        self.container_ref
    }
    fn read_ref(&self) -> VmResult<Value<F>> {
        let value = match &*self.container_ref.container() {
            Container::Locals(_) => unreachable!("IndexedGlobalRef should point to a struct"),
            Container::Struct(r) => r.borrow()[self.element_idx].copy_value()?,
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
            (Container::Locals(_), _) => unreachable!("IndexedGlobalRef should point to a struct"),
            (Container::Struct(r), _) => {
                let mut v = r.borrow_mut();
                v[self.element_idx] = x;
            }
        }
        Ok(())
    }
    fn copy_value(&self) -> Self {
        Self {
            element_idx: self.element_idx,
            container_ref: self.container_ref.copy_value(),
        }
    }
}

// A reference pointing to an element in a container.
#[derive(Clone, Debug)]
pub enum IndexedRef<F: FieldExt> {
    IndexedLocalsRef(IndexedLocalsRef<F>), // reference pointing to a local (an element of locals).
    IndexedStructRef(IndexedStructRef<F>), // reference pointing to an element of a local struct.
    IndexedGlobalRef(IndexedGlobalRef<F>), // reference pointing to an element of a global value.
}

impl<F: FieldExt> IndexedRef<F> {
    pub fn container(&self) -> &Container<F> {
        match self {
            Self::IndexedLocalsRef(r) => r.container(),
            Self::IndexedStructRef(r) => r.container(),
            Self::IndexedGlobalRef(r) => r.container(),
        }
    }
    pub fn container_ref(self) -> ContainerRef<F> {
        match self {
            Self::IndexedLocalsRef(r) => r.container_ref(),
            Self::IndexedStructRef(r) => r.container_ref(),
            Self::IndexedGlobalRef(r) => r.container_ref(),
        }
    }
    fn read_ref(&self) -> VmResult<Value<F>> {
        match self {
            Self::IndexedLocalsRef(r) => r.read_ref(),
            Self::IndexedStructRef(r) => r.read_ref(),
            Self::IndexedGlobalRef(r) => r.read_ref(),
        }
    }
    fn write_ref(&mut self, x: Value<F>) -> VmResult<()> {
        match self {
            Self::IndexedLocalsRef(r) => r.write_ref(x),
            Self::IndexedStructRef(r) => r.write_ref(x),
            Self::IndexedGlobalRef(r) => r.write_ref(x),
        }
    }
    pub fn index(&self) -> usize {
        match self {
            Self::IndexedLocalsRef(r) => r.index(),
            Self::IndexedStructRef(r) => r.index(),
            Self::IndexedGlobalRef(_) => unimplemented!(),
        }
    }
    fn call_index(&self) -> usize {
        match self {
            Self::IndexedLocalsRef(r) => r.call_index(),
            Self::IndexedStructRef(r) => r.call_index(),
            Self::IndexedGlobalRef(_) => unimplemented!(),
        }
    }
    fn copy_value(&self) -> Self {
        match self {
            Self::IndexedLocalsRef(r) => Self::IndexedLocalsRef(r.copy_value()),
            Self::IndexedStructRef(r) => Self::IndexedStructRef(r.copy_value()),
            Self::IndexedGlobalRef(r) => Self::IndexedGlobalRef(r.copy_value()),
        }
    }
    fn is_global(&self) -> bool {
        matches!(self, Self::IndexedGlobalRef(_)) // element of a global value.
    }
}

// Reference is used to support read_ref and write_ref.
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
    pub fn call_index(&self) -> usize {
        match self {
            Self::ContainerRef(_) => unimplemented!(),
            Self::IndexedRef(r) => r.call_index(),
        }
    }

    pub fn is_global(&self) -> bool {
        match self {
            Self::ContainerRef(r) => r.is_global(),
            Self::IndexedRef(r) => r.is_global(),
        }
    }
}

// StructRef is used to support borrow_element
#[derive(Debug, Clone)]
pub enum StructRef<F: FieldExt> {
    // local Struct value
    LocalStructRef(IndexedLocalsRef<F>),
    // GlobalValue
    GlobalStructRef(ContainerRef<F>),
}

impl<F: FieldExt> StructRef<F> {
    pub fn borrow_element(&self, field_idx: usize) -> VmResult<Value<F>> {
        match self {
            Self::LocalStructRef(r) => r.borrow_element(field_idx),
            Self::GlobalStructRef(r) => r.borrow_global_value_element(field_idx),
        }
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
    // No resource resides in this slot or in storage.
    None,
    // A resource has been published to this slot and it did not previously exist in storage.
    Fresh {
        fields: Rc<RefCell<Vec<Value<F>>>>,
    },
    // A resource resides in this slot and also in storage. The status flag indicates whether
    // it has potentially been altered.
    Cached {
        fields: Rc<RefCell<Vec<Value<F>>>>,
        status: Rc<RefCell<GlobalDataStatus>>,
    },
    // A resource used to exist in storage but has been deleted by the current transaction.
    Deleted,
}

impl<F: FieldExt> GlobalValue<F> {
    pub fn none() -> Self {
        GlobalValue::None
    }

    fn fresh(val: Value<F>) -> VmResult<Self> {
        match val {
            Value::Container(Container::Struct(fields)) => Ok(Self::Fresh { fields }),
            _ => Err(
                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    .with_message("not a resource type".to_string()),
            ),
        }
    }

    fn cached(val: Value<F>, status: GlobalDataStatus) -> VmResult<Self> {
        match val {
            Value::Container(Container::Struct(fields)) => {
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
        Ok(Value::Container(Container::Struct(fields)))
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

    pub fn borrow_global(&self) -> VmResult<Value<F>> {
        match self {
            Self::None | Self::Deleted => Err(RuntimeError::new(StatusCode::MissingData)),
            Self::Fresh { fields } => Ok(Value::ContainerRef(ContainerRef::Global(
                Container::Struct(Rc::clone(fields)),
            ))),
            Self::Cached { fields, status: _ } => Ok(Value::ContainerRef(ContainerRef::Global(
                Container::Struct(Rc::clone(fields)),
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
    pub fn new_variable(value: Option<F>, cell: Option<Cell>, ty: MoveValueType) -> VmResult<Self> {
        match ty {
            MoveValueType::U8 => Ok(Value::U8(U8 { value, cell })),
            MoveValueType::U64 => Ok(Value::U64(U64 { value, cell })),
            MoveValueType::U128 => Ok(Value::U128(U128 { value, cell })),
            MoveValueType::Bool => Ok(Value::Bool(Bool { value, cell })),
            MoveValueType::Signer => Ok(Value::signer(AccountAddress::new(
                value.expect("address should not be None"),
            ))),
            MoveValueType::Address => Ok(Value::address(
                AccountAddress::new(value.expect("address should not be None")),
                cell,
            )),
            _ => unimplemented!(),
        }
    }
    pub fn bool(x: bool, cell: Option<Cell>) -> VmResult<Self> {
        let value = if x { F::one() } else { F::zero() };
        Ok(Self::Bool(Bool {
            value: Some(value),
            cell,
        }))
    }
    pub fn u8(x: u8, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u128(x as u128);
        Ok(Self::U8(U8 {
            value: Some(value),
            cell,
        }))
    }
    pub fn u64(x: u64, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u128(x as u128);
        Ok(Self::U64(U64 {
            value: Some(value),
            cell,
        }))
    }
    pub fn u128(x: u128, cell: Option<Cell>) -> VmResult<Self> {
        let value = F::from_u128(x);
        Ok(Self::U128(U128 {
            value: Some(value),
            cell,
        }))
    }
    pub fn address(x: AccountAddress<F>, cell: Option<Cell>) -> Self {
        Self::Address(Address {
            account_address: Some(x),
            cell,
        })
    }

    pub fn signer(x: AccountAddress<F>) -> Self {
        Self::Container(Container::signer(x))
    }

    pub fn struct_(s: Struct<F>) -> Self {
        Self::Container(Container::Struct(Rc::new(RefCell::new(s.fields))))
    }
    pub fn value(&self) -> Option<F> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => v.value,
            Self::U64(v) => v.value,
            Self::U128(v) => v.value,
            Self::Bool(v) => v.value,
            Self::Address(addr) => addr.value(),
            Self::Container(c) => c.value(),
            Self::IndexedRef(r) => r.container().value(),
            Self::ContainerRef(r) => r.container().value(),
        }
    }
    pub fn cell(&self) -> Option<Cell> {
        match self {
            Self::Invalid => None,
            Self::U8(v) => v.cell,
            Self::U64(v) => v.cell,
            Self::U128(v) => v.cell,
            Self::Bool(v) => v.cell,
            _ => unimplemented!(),
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
            (Self::U8(v1), Self::U8(v2)) => v1.value.unwrap() == v2.value.unwrap(),
            (Self::U64(v1), Self::U64(v2)) => v1.value.unwrap() == v2.value.unwrap(),
            (Self::U128(v1), Self::U128(v2)) => v1.value.unwrap() == v2.value.unwrap(),
            (Self::Bool(v1), Self::Bool(v2)) => v1.value.unwrap() == v2.value.unwrap(),
            _ => false,
        }
    }

    pub fn less_than(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 < v2),
            _ => Err(RuntimeError::new(StatusCode::InternalError)),
        }
    }

    pub fn less_equal(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 <= v2),
            _ => Err(RuntimeError::new(StatusCode::InternalError)),
        }
    }

    pub fn greater_than(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 > v2),
            _ => Err(RuntimeError::new(StatusCode::InternalError)),
        }
    }

    pub fn greater_equal(&self, other: &Self) -> VmResult<bool> {
        match (self.value(), other.value()) {
            (Some(v1), Some(v2)) => Ok(v1 >= v2),
            _ => Err(RuntimeError::new(StatusCode::InternalError)),
        }
    }

    pub fn is_zero(&self) -> bool {
        match self.value() {
            Some(v) => v.is_zero_vartime(),
            None => false,
        }
    }

    pub fn div_rem(&self, other: Value<F>) -> VmResult<(Value<F>, Value<F>)> {
        let l_move: Option<MoveValue> = self.clone().into();
        let r_move: Option<MoveValue> = other.into();
        match (l_move, r_move) {
            (Some(l), Some(r)) => {
                let quo = move_div(l.clone(), r.clone())?;
                let rem = move_rem(l, r)?;
                let quo_field = Some(convert_to_field::<F>(quo));
                let rem_field = Some(convert_to_field::<F>(rem));
                let quo_value = Value::new_variable(quo_field, None, self.ty())?;
                let rem_value = Value::new_variable(rem_field, None, self.ty())?;
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
        // todo: handle type mismatch
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => Some(F::from_u128(
                u8::checked_add(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U64, MoveValueType::U64) => Some(F::from_u128(
                u64::checked_add(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U128, MoveValueType::U128) => Some(F::from_u128(
                u128::checked_add(lhs, rhs).expect("arithmetic error found"),
            )),
            (_, _) => unimplemented!(),
        };
        let c = Value::new_variable(value, None, self.ty())?;
        Ok(c)
    }
}

impl<F: FieldExt> Sub for Value<F> {
    type Output = VmResult<Self>;

    fn sub(self, b: Value<F>) -> Self::Output {
        // implement sub based on checked_sub API to check arithmetic overflow
        //let value = self.value().and_then(|a| b.value().map(|b| a - b));
        // todo: handle type mismatch
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => Some(F::from_u128(
                u8::checked_sub(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U64, MoveValueType::U64) => Some(F::from_u128(
                u64::checked_sub(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U128, MoveValueType::U128) => Some(F::from_u128(
                u128::checked_sub(lhs, rhs).expect("arithmetic error found"),
            )),
            (_, _) => unimplemented!(),
        };
        let c = Value::new_variable(value, None, self.ty())?;
        Ok(c)
    }
}

impl<F: FieldExt> Mul for Value<F> {
    type Output = VmResult<Self>;

    fn mul(self, b: Value<F>) -> Self::Output {
        // implement mul based on checked_mul API to check arithmetic overflow
        // let value = self.value().and_then(|a| b.value().map(|b| a * b));
        // todo: handle type mismatch
        let lhs = self.value().unwrap().get_lower_128();
        let rhs = b.value().unwrap().get_lower_128();
        let value = match (self.ty(), b.ty()) {
            (MoveValueType::U8, MoveValueType::U8) => Some(F::from_u128(
                u8::checked_mul(lhs as u8, rhs as u8).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U64, MoveValueType::U64) => Some(F::from_u128(
                u64::checked_mul(lhs as u64, rhs as u64).expect("arithmetic error found") as u128,
            )),
            (MoveValueType::U128, MoveValueType::U128) => Some(F::from_u128(
                u128::checked_mul(lhs, rhs).expect("arithmetic error found"),
            )),
            (_, _) => unimplemented!(),
        };
        let c = Value::new_variable(value, None, self.ty())?;
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
                let v = Some(convert_to_field::<F>(quo));
                let value = Value::new_variable(v, None, self.ty())?;
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
                let v = Some(convert_to_field::<F>(rem));
                let value = Value::new_variable(v, None, self.ty())?;
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
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }
}

impl<F: FieldExt> Value<F> {
    pub fn eq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = match (a.value(), b.value()) {
            (Some(a), Some(b)) => {
                let fr = if a == b { F::one() } else { F::zero() };
                Some(fr)
            }
            _ => None,
        };

        let c = Value::new_variable(value, None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn neq(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if !a.equals(&b) { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn lt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lt = a.less_than(&b)?;
        let value = if lt { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn le(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let le = a.less_equal(&b)?;
        let value = if le { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn gt(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let gt = a.greater_than(&b)?;
        let value = if gt { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn ge(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let ge = a.greater_equal(&b)?;
        let value = if ge { F::one() } else { F::zero() };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn and(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() || b.is_zero() {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn or(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let value = if a.is_zero() && b.is_zero() {
            F::zero()
        } else {
            F::one()
        };
        let c = Value::new_variable(Some(value), None, MoveValueType::Bool)?;
        Ok(c)
    }

    pub fn delta_invert(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let delta_invert = if a.value() == b.value() {
            F::one()
        } else {
            let delta = a.value().unwrap() - b.value().unwrap();
            delta.invert().unwrap()
        };

        let value = Value::new_variable(Some(delta_invert), None, a.ty())?;
        Ok(value)
    }

    pub fn diff(a: Value<F>, b: Value<F>) -> VmResult<Value<F>> {
        let lhs = a.value().unwrap();
        let rhs = b.value().unwrap();
        let range = F::from(2).pow(&[(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);
        let range_or_zero = if lhs < rhs { range } else { F::zero() };
        let diff = (lhs - rhs) + range_or_zero;
        let value = Value::new_variable(Some(diff), None, a.ty())?;
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

impl<F: FieldExt> Value<F> {
    pub fn copy_value(&self) -> VmResult<Self> {
        Ok(match self {
            Value::Invalid => Value::Invalid,
            Value::Container(c) => Value::Container(c.copy_value()?),
            Value::ContainerRef(r) => Value::ContainerRef(r.copy_value()),
            Value::IndexedRef(r) => Value::IndexedRef(r.copy_value()),
            v => v.clone(), // directly clone() for U8, U64, U128, Bool
        })
    }
}

impl<F: FieldExt> Container<F> {
    pub fn copy_value(&self) -> VmResult<Self> {
        Ok(match self {
            Self::Struct(r) => {
                let struct_ = Rc::new(RefCell::new(
                    r.borrow()
                        .iter()
                        .map(|v| v.copy_value())
                        .collect::<VmResult<_>>()?,
                ));
                Self::Struct(struct_)
            }
            Self::Locals(l) => Self::Locals(l.clone()),
        })
    }

    pub fn copy_by_ref(&self) -> Self {
        match self {
            Self::Struct(r) => Self::Struct(Rc::clone(r)),
            Self::Locals(r) => Self::Locals(Rc::clone(r)),
        }
    }
}

impl<F: FieldExt> Clone for Container<F> {
    fn clone(&self) -> Self {
        self.copy_value()
            .expect("Container copy_value() should succeed")
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
