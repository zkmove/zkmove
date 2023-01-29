// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::rw_table::RWTarget;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::AssignedCell;
use movelang::account_address::AccountAddress;
use movelang::value::Value;
use std::cmp::Ordering;
use std::convert::From;

#[derive(Clone, Debug)]
pub struct ConvertedRWOperation<F: FieldExt> {
    pub(crate) gc: (F, Option<AssignedCell<F, F>>),
    pub(crate) rw_target: (F, Option<AssignedCell<F, F>>),
    pub(crate) rw: (F, Option<AssignedCell<F, F>>),
    pub(crate) frame_index: (F, Option<AssignedCell<F, F>>),
    pub(crate) address: (F, Option<AssignedCell<F, F>>),
    pub(crate) nested_address_0: (F, Option<AssignedCell<F, F>>),
    pub(crate) nested_address_1: (F, Option<AssignedCell<F, F>>),
    pub(crate) value: (Option<F>, Option<AssignedCell<F, F>>),
    //struct definition index, only used by global ops
    pub(crate) sd_index: (F, Option<AssignedCell<F, F>>),
}

impl<F: FieldExt> ConvertedRWOperation<F> {
    pub fn empty() -> Self {
        Self {
            gc: (F::from_u128(0u128), None),
            rw_target: (F::from_u128(0u128), None),
            rw: (F::from_u128(0u128), None),
            frame_index: (F::from_u128(0u128), None),
            address: (F::from_u128(0u128), None),
            nested_address_0: (F::from_u128(0u128), None),
            nested_address_1: (F::from_u128(0u128), None),
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
            5 => Ok(self.nested_address_0.0),
            6 => Ok(self.nested_address_1.0),
            7 => self
                .value
                .0
                .ok_or_else(|| RuntimeError::new(StatusCode::ShouldNotReachHere)),
            8 => Ok(self.sd_index.0),
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
                self.nested_address_0 = (self.nested_address_0.0, cell);
                Ok(())
            }
            6 => {
                self.nested_address_1 = (self.nested_address_1.0, cell);
                Ok(())
            }
            7 => {
                self.value = (self.value.0, cell);
                Ok(())
            }
            8 => {
                self.sd_index = (self.sd_index.0, cell);
                Ok(())
            }
            _ => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RW {
    READ = 0,
    WRITE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalsOp<F: FieldExt> {
    pub frame_index: usize, // locals ops will sorted by (frame_index, index, gc)
    pub index: usize,
    pub nested_address_0: usize,
    pub nested_address_1: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> LocalsOp<F> {
    pub fn empty() -> Self {
        Self {
            frame_index: 0,
            index: 0,
            nested_address_0: 0,
            nested_address_1: 0,
            gc: 0,
            rw: RW::READ,
            value: Value::u64(0),
        }
    }
}

impl<F: FieldExt> PartialOrd for LocalsOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for LocalsOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.frame_index,
            &self.index,
            &self.nested_address_0,
            &self.nested_address_1,
            &self.gc,
        )
            .cmp(&(
                &other.frame_index,
                &other.index,
                &other.nested_address_0,
                &other.nested_address_1,
                &other.gc,
            ))
    }
}

// convert LocalsOp into a vector of field value
impl<F: FieldExt> From<&LocalsOp<F>> for ConvertedRWOperation<F> {
    fn from(rw_op: &LocalsOp<F>) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Locals as u128), None),
            rw: (F::from_u128(rw_op.rw.clone() as u128), None),
            frame_index: (F::from_u128(rw_op.frame_index as u128), None),
            address: (F::from_u128(rw_op.index as u128), None),
            nested_address_0: (F::from_u128(rw_op.nested_address_0 as u128), None),
            nested_address_1: (F::from_u128(rw_op.nested_address_1 as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(0), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOp<F: FieldExt> {
    pub address: usize, // stack ops will be sorted by (address, gc)
    pub nested_address_0: usize,
    pub nested_address_1: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> StackOp<F> {
    pub fn empty() -> Self {
        Self {
            address: 0,
            nested_address_0: 0,
            nested_address_1: 0,
            value: Value::u64(0),
            rw: RW::READ,
            gc: 0,
        }
    }
}

impl<F: FieldExt> PartialOrd for StackOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for StackOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.address,
            &self.nested_address_0,
            &self.nested_address_1,
            &self.gc,
        )
            .cmp(&(
                &other.address,
                &other.nested_address_0,
                &other.nested_address_1,
                &other.gc,
            ))
    }
}

// convert StackOp into a vector of field value
impl<F: FieldExt> From<&StackOp<F>> for ConvertedRWOperation<F> {
    fn from(rw_op: &StackOp<F>) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Stack as u128), None),
            rw: (F::from_u128(rw_op.rw.clone() as u128), None),
            frame_index: (F::from_u128(0), None),
            address: (F::from_u128(rw_op.address as u128), None),
            nested_address_0: (F::from_u128(rw_op.nested_address_0 as u128), None),
            nested_address_1: (F::from_u128(rw_op.nested_address_1 as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(0), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalOp<F: FieldExt> {
    pub address: AccountAddress<F>, // global ops will be sorted by (address, sd_index, gc)
    pub sd_index: usize,            // struct definition index
    pub nested_address_0: usize,
    pub nested_address_1: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> GlobalOp<F> {
    pub fn empty() -> Self {
        Self {
            address: AccountAddress::zero(),
            sd_index: 0,
            nested_address_0: 0,
            nested_address_1: 0,
            value: Value::u64(0),
            rw: RW::READ,
            gc: 0,
        }
    }
}

impl<F: FieldExt> PartialOrd for GlobalOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for GlobalOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            &self.address,
            &self.sd_index,
            &self.nested_address_0,
            &self.nested_address_1,
            &self.gc,
        )
            .cmp(&(
                &other.address,
                &other.sd_index,
                &other.nested_address_0,
                &other.nested_address_1,
                &other.gc,
            ))
    }
}

// convert GlobalOp into a vector of field value
impl<F: FieldExt> From<&GlobalOp<F>> for ConvertedRWOperation<F> {
    fn from(rw_op: &GlobalOp<F>) -> ConvertedRWOperation<F> {
        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc as u128), None),
            rw_target: (F::from_u128(RWTarget::Global as u128), None),
            rw: (F::from_u128(rw_op.rw.clone() as u128), None),
            frame_index: (F::from_u128(0), None),
            address: (rw_op.address.value(), None),
            nested_address_0: (F::from_u128(rw_op.nested_address_0 as u128), None),
            nested_address_1: (F::from_u128(rw_op.nested_address_1 as u128), None),
            value: (value, None),
            sd_index: (F::from_u128(0), None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWOperation<F: FieldExt> {
    LocalsOp(LocalsOp<F>),
    StackOp(StackOp<F>),
    GlobalOp(GlobalOp<F>),
}

impl<F: FieldExt> RWOperation<F> {
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
            Self::StackOp(op) => op.rw.clone(),
            Self::LocalsOp(op) => op.rw.clone(),
            Self::GlobalOp(op) => op.rw.clone(),
        }
    }

    pub fn frame_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(op) => op.frame_index,
            Self::GlobalOp(_) => 0,
        }
    }

    pub fn value(&self) -> Value<F> {
        match self {
            Self::StackOp(op) => op.value.clone(),
            Self::LocalsOp(op) => op.value.clone(),
            Self::GlobalOp(op) => op.value.clone(),
        }
    }

    pub fn sd_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(_) => 0,
            Self::GlobalOp(op) => op.sd_index,
        }
    }

    pub fn account_address(&self) -> AccountAddress<F> {
        match self {
            Self::StackOp(_) => unimplemented!(),
            Self::LocalsOp(_) => unimplemented!(),
            Self::GlobalOp(op) => op.address,
        }
    }
}

// convert RWOperation into a vector of field value
impl<F: FieldExt> From<&RWOperation<F>> for ConvertedRWOperation<F> {
    fn from(rw_op: &RWOperation<F>) -> ConvertedRWOperation<F> {
        let value = match rw_op.value() {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value().value(),
        };

        let address_value = match rw_op {
            RWOperation::StackOp(op) => F::from_u128(op.address as u128),
            RWOperation::LocalsOp(op) => F::from_u128(op.index as u128),
            RWOperation::GlobalOp(op) => op.address.value(),
        };

        let nested_address_0_value = match rw_op {
            RWOperation::StackOp(op) => F::from_u128(op.nested_address_0 as u128),
            RWOperation::LocalsOp(op) => F::from_u128(op.nested_address_0 as u128),
            RWOperation::GlobalOp(op) => F::from_u128(op.nested_address_0 as u128),
        };

        let nested_address_1_value = match rw_op {
            RWOperation::StackOp(op) => F::from_u128(op.nested_address_1 as u128),
            RWOperation::LocalsOp(op) => F::from_u128(op.nested_address_1 as u128),
            RWOperation::GlobalOp(op) => F::from_u128(op.nested_address_1 as u128),
        };

        ConvertedRWOperation {
            gc: (F::from_u128(rw_op.gc() as u128), None),
            rw_target: (F::from_u128(rw_op.rw_target() as u128), None),
            rw: (F::from_u128(rw_op.rw() as u128), None),
            frame_index: (F::from_u128(rw_op.frame_index() as u128), None),
            address: (address_value, None),
            nested_address_0: (nested_address_0_value, None),
            nested_address_1: (nested_address_1_value, None),
            value: (value, None),
            sd_index: (F::from_u128(rw_op.sd_index() as u128), None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RWOperations<F: FieldExt>(pub Vec<RWOperation<F>>);

impl<F: FieldExt> From<RWOperations<F>>
    for (SortedStackOps<F>, SortedLocalsOps<F>, SortedGlobalOps<F>)
{
    fn from(
        rw_operations: RWOperations<F>,
    ) -> (SortedStackOps<F>, SortedLocalsOps<F>, SortedGlobalOps<F>) {
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
pub struct SortedStackOps<F: FieldExt>(pub Vec<StackOp<F>>);

// convert SortedStackOps into field values
impl<F: FieldExt> From<&SortedStackOps<F>> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedStackOps<F>) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedLocalsOps<F: FieldExt>(pub Vec<LocalsOp<F>>);

// convert SortedLocalsOps into field values
impl<F: FieldExt> From<&SortedLocalsOps<F>> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedLocalsOps<F>) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedGlobalOps<F: FieldExt>(pub Vec<GlobalOp<F>>);

// convert SortedGlobalOps into field values
impl<F: FieldExt> From<&SortedGlobalOps<F>> for Vec<ConvertedRWOperation<F>> {
    fn from(rw_ops: &SortedGlobalOps<F>) -> Vec<ConvertedRWOperation<F>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}
