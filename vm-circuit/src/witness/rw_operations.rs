// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::rw_table::RWTarget;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::circuit::AssignedCell;
use movelang::account_address::AccountAddress;
use movelang::value::{SimpleValue, Value};
use std::cmp::Ordering;
use std::convert::From;
use types::Field;

#[derive(Clone, Debug)]
pub struct ConvertedRWOperation<F: Field> {
    pub(crate) gc: (F, Option<AssignedCell<F, F>>),
    pub(crate) rw_target: (F, Option<AssignedCell<F, F>>),
    pub(crate) rw: (F, Option<AssignedCell<F, F>>),
    pub(crate) frame_index: (F, Option<AssignedCell<F, F>>),
    pub(crate) address: (F, Option<AssignedCell<F, F>>),
    pub(crate) address_ext: (F, Option<AssignedCell<F, F>>),
    pub(crate) value: (Option<F>, Option<AssignedCell<F, F>>),
    //struct definition index, only used by global ops
    pub(crate) sd_index: (F, Option<AssignedCell<F, F>>),
}

impl<F: Field> ConvertedRWOperation<F> {
    pub fn empty() -> Self {
        Self {
            gc: (F::from_u128(0u128), None),
            rw_target: (F::from_u128(0u128), None),
            rw: (F::from_u128(0u128), None),
            frame_index: (F::from_u128(0u128), None),
            address: (F::from_u128(0u128), None),
            address_ext: (F::from_u128(0u128), None),
            value: (Some(F::from_u128(0u128)), None),
            sd_index: (F::from_u128(0u128), None),
        }
    }
    pub fn get_field(&mut self, index: usize) -> VmResult<F> {
        match index {
            0 => Ok(self.gc.0),
            1 => Ok(self.rw_target.0),
            2 => Ok(self.rw.0),
            3 => Ok(self.frame_index.0),
            4 => Ok(self.address.0),
            5 => Ok(self.address_ext.0),
            6 => self
                .value
                .0
                .ok_or_else(|| RuntimeError::new(StatusCode::ShouldNotReachHere)),
            7 => Ok(self.sd_index.0),
            _ => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
    pub fn assign_cell(&mut self, index: usize, cell: Option<AssignedCell<F, F>>) -> VmResult<()> {
        match index {
            0 => {
                self.gc = (self.gc.0, cell);
                Ok(())
            }
            1 => {
                self.rw_target = (self.rw_target.0, cell);
                Ok(())
            }
            2 => {
                self.rw = (self.rw.0, cell);
                Ok(())
            }
            3 => {
                self.frame_index = (self.frame_index.0, cell);
                Ok(())
            }
            4 => {
                self.address = (self.address.0, cell);
                Ok(())
            }
            5 => {
                self.address_ext = (self.address_ext.0, cell);
                Ok(())
            }
            6 => {
                self.value = (self.value.0, cell);
                Ok(())
            }
            7 => {
                self.sd_index = (self.sd_index.0, cell);
                Ok(())
            }
            _ => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RW {
    READ = 0,
    WRITE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalsOp {
    pub frame_index: usize, // locals ops will sorted by (frame_index, index, gc)
    pub index: usize,
    pub address_ext: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Option<SimpleValue>,
}

impl LocalsOp {
    pub fn empty() -> Self {
        Self {
            frame_index: 0,
            index: 0,
            address_ext: 0,
            gc: 0,
            rw: RW::READ,
            value: Some(SimpleValue::u64(0)),
        }
    }
}

impl PartialOrd for LocalsOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LocalsOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.frame_index, &self.index, &self.address_ext, &self.gc).cmp(&(
            &other.frame_index,
            &other.index,
            &other.address_ext,
            &other.gc,
        ))
    }
}

// convert LocalsOp into a vector of field value
impl<F: Field> From<&LocalsOp> for ConvertedRWOperation<F> {
    fn from(rw_op: &LocalsOp) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            None => Some(F::ZERO), // todo: how to distinguish with Value::Constant(0)
            Some(v) => v.field_value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Locals as u128), None),
            rw: (F::from_u128(rw_op.rw as u128), None),
            frame_index: (F::from_u128(rw_op.frame_index as u128), None),
            address: (F::from_u128(rw_op.index as u128), None),
            address_ext: (F::from_u128(rw_op.address_ext as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(0), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOp {
    pub address: usize, // stack ops will be sorted by (address, gc)
    pub address_ext: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Option<SimpleValue>,
}

impl StackOp {
    pub fn empty() -> Self {
        Self {
            address: 0,
            address_ext: 0,
            value: Some(SimpleValue::u64(0)),
            rw: RW::READ,
            gc: 0,
        }
    }
}

impl PartialOrd for StackOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StackOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.address, &self.address_ext, &self.gc).cmp(&(
            &other.address,
            &other.address_ext,
            &other.gc,
        ))
    }
}

// convert StackOp into a vector of field value
impl<F: Field> From<&StackOp> for ConvertedRWOperation<F> {
    fn from(rw_op: &StackOp) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            None => Some(F::ZERO), // todo: how to distinguish with Value::Constant(0)
            Some(v) => v.field_value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Stack as u128), None),
            rw: (F::from_u128(rw_op.rw as u128), None),
            frame_index: (F::from_u128(0), None),
            address: (F::from_u128(rw_op.address as u128), None),
            address_ext: (F::from_u128(rw_op.address_ext as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(0), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalOp {
    pub address: AccountAddress, // global ops will be sorted by (address, sd_index, gc)
    pub sd_index: usize,         // struct definition index
    pub address_ext: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Option<SimpleValue>,
}

impl GlobalOp {
    pub fn empty() -> Self {
        Self {
            address: AccountAddress::zero(),
            sd_index: 0,
            address_ext: 0,
            value: Some(SimpleValue::u64(0)),
            rw: RW::READ,
            gc: 0,
        }
    }
}

impl PartialOrd for GlobalOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GlobalOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.address, &self.sd_index, &self.address_ext, &self.gc).cmp(&(
            &other.address,
            &other.sd_index,
            &other.address_ext,
            &other.gc,
        ))
    }
}

// convert GlobalOp into a vector of field value
impl<F: Field> From<&GlobalOp> for ConvertedRWOperation<F> {
    fn from(rw_op: &GlobalOp) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            None => Some(F::ZERO), // todo: how to distinguish with Value::Constant(0)
            Some(v) => v.field_value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Global as u128), None),
            rw: (F::from_u128(rw_op.rw as u128), None),
            frame_index: (F::from_u128(0), None),
            address: (rw_op.address.field_value(), None),
            address_ext: (F::from_u128(rw_op.address_ext as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(rw_op.sd_index as u128), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWOperation {
    LocalsOp(LocalsOp),
    StackOp(StackOp),
    GlobalOp(GlobalOp),
}

impl RWOperation {
    pub fn is_stack_op(&self) -> bool {
        matches!(self, Self::StackOp(_))
    }

    pub fn is_locals_op(&self) -> bool {
        matches!(self, Self::LocalsOp(_))
    }

    pub fn is_global_op(&self) -> bool {
        matches!(self, Self::GlobalOp(_))
    }

    pub fn gc(&self) -> usize {
        match self {
            Self::StackOp(op) => op.gc,
            Self::LocalsOp(op) => op.gc,
            Self::GlobalOp(op) => op.gc,
        }
    }

    pub fn rw_target(&self) -> RWTarget {
        match self {
            Self::StackOp(_) => RWTarget::Stack,
            Self::LocalsOp(_) => RWTarget::Locals,
            Self::GlobalOp(_) => RWTarget::Global,
        }
    }

    pub fn rw(&self) -> RW {
        match self {
            Self::StackOp(op) => op.rw,
            Self::LocalsOp(op) => op.rw,
            Self::GlobalOp(op) => op.rw,
        }
    }

    pub fn frame_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(op) => op.frame_index,
            Self::GlobalOp(_) => 0,
        }
    }

    pub fn value(&self) -> Value {
        let v = match self {
            Self::StackOp(op) => op.value,
            Self::LocalsOp(op) => op.value,
            Self::GlobalOp(op) => op.value,
        };
        v.map(Into::into).unwrap_or_else(|| Value::Invalid)
    }

    pub fn sd_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(_) => 0,
            Self::GlobalOp(op) => op.sd_index,
        }
    }

    pub fn account_address(&self) -> AccountAddress {
        match self {
            Self::StackOp(_) => unimplemented!(),
            Self::LocalsOp(_) => unimplemented!(),
            Self::GlobalOp(op) => op.address,
        }
    }

    pub fn address_ext(&self) -> usize {
        match self {
            Self::StackOp(op) => op.address_ext,
            Self::LocalsOp(op) => op.address_ext,
            Self::GlobalOp(op) => op.address_ext,
        }
    }

    pub fn address(&self) -> usize {
        match self {
            Self::StackOp(op) => op.address,
            Self::LocalsOp(op) => op.index,
            Self::GlobalOp(_) => unreachable!(),
        }
    }
}

// convert RWOperation into a vector of field value
impl<F: Field> From<&RWOperation> for ConvertedRWOperation<F> {
    fn from(rw_op: &RWOperation) -> ConvertedRWOperation<F> {
        let value = match rw_op.value() {
            Value::Invalid => Some(F::ZERO), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value().field_value(),
        };

        let address_value = match rw_op {
            RWOperation::StackOp(op) => F::from_u128(op.address as u128),
            RWOperation::LocalsOp(op) => F::from_u128(op.index as u128),
            RWOperation::GlobalOp(op) => op.address.field_value(),
        };

        let address_ext_value = match rw_op {
            RWOperation::StackOp(op) => F::from_u128(op.address_ext as u128),
            RWOperation::LocalsOp(op) => F::from_u128(op.address_ext as u128),
            RWOperation::GlobalOp(op) => F::from_u128(op.address_ext as u128),
        };

        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc() as u128), None),
            rw_target: (F::from_u128(rw_op.rw_target() as u128), None),
            rw: (F::from_u128(rw_op.rw() as u128), None),
            frame_index: (F::from_u128(rw_op.frame_index() as u128), None),
            address: (address_value, None),
            address_ext: (address_ext_value, None),
            value: (value, None),
            sd_index: (F::from_u128(rw_op.sd_index() as u128), None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RWOperations(pub Vec<RWOperation>);

impl From<RWOperations> for (SortedStackOps, SortedLocalsOps, SortedGlobalOps) {
    fn from(rw_operations: RWOperations) -> (SortedStackOps, SortedLocalsOps, SortedGlobalOps) {
        let mut stack_ops = Vec::new();
        let mut locals_ops = Vec::new();
        let mut global_ops = Vec::new();
        rw_operations.0.into_iter().for_each(|op| match op {
            RWOperation::StackOp(stack_op) => stack_ops.push(stack_op),
            RWOperation::LocalsOp(locals_op) => locals_ops.push(locals_op),
            RWOperation::GlobalOp(global_op) => global_ops.push(global_op),
        });
        stack_ops.sort();
        locals_ops.sort();
        global_ops.sort();
        (
            SortedStackOps(stack_ops),
            SortedLocalsOps(locals_ops),
            SortedGlobalOps(global_ops),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedStackOps(pub Vec<StackOp>);

// convert SortedStackOps into field values
impl<F: Field> From<&SortedStackOps> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedStackOps) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedLocalsOps(pub Vec<LocalsOp>);

// convert SortedLocalsOps into field values
impl<F: Field> From<&SortedLocalsOps> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedLocalsOps) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedGlobalOps(pub Vec<GlobalOp>);

// convert SortedGlobalOps into field values
impl<F: Field> From<&SortedGlobalOps> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedGlobalOps) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}
