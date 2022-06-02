// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::RWTarget;
use halo2_proofs::arithmetic::FieldExt;
use std::cmp::Ordering;
use std::convert::From;
use types::value::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RW {
    READ = 0,
    WRITE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalsOp<F: FieldExt> {
    pub call_index: usize, // locals ops will sorted by (call_index, index, gc)
    pub index: usize,
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> PartialOrd for LocalsOp<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FieldExt> Ord for LocalsOp<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.call_index, &self.index, &self.gc).cmp(&(&other.call_index, &other.index, &other.gc))
    }
}

// convert LocalsOp into a vector of field value
impl<F: FieldExt> From<&LocalsOp<F>> for Vec<Option<F>> {
    fn from(rw_op: &LocalsOp<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc as u128)));
        field_values.push(Some(F::from_u128(RWTarget::Locals as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw.clone() as u128)));
        field_values.push(Some(F::from_u128(rw_op.call_index as u128)));
        field_values.push(Some(F::from_u128(rw_op.index as u128)));

        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOp<F: FieldExt> {
    pub address: usize, // stack ops will be sorted by (address, gc)
    pub gc: usize,
    pub rw: RW,
    pub value: Value<F>,
}

impl<F: FieldExt> StackOp<F> {
    pub fn empty() -> Self {
        Self {
            address: 0,
            value: Value::u64(0, None).unwrap(),
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
        (&self.address, &self.gc).cmp(&(&other.address, &other.gc))
    }
}

// convert StackOp into a vector of field value
impl<F: FieldExt> From<&StackOp<F>> for Vec<Option<F>> {
    fn from(rw_op: &StackOp<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc as u128)));
        field_values.push(Some(F::from_u128(RWTarget::Stack as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw.clone() as u128)));
        field_values.push(Some(F::from_u128(0)));
        field_values.push(Some(F::from_u128(rw_op.address as u128)));

        let value = match rw_op.value {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value.value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWOperation<F: FieldExt> {
    LocalsOp(LocalsOp<F>),
    StackOp(StackOp<F>),
}

impl<F: FieldExt> RWOperation<F> {
    pub fn is_stack_op(&self) -> bool {
        match self {
            Self::StackOp(_) => true,
            _ => false,
        }
    }

    pub fn is_locals_op(&self) -> bool {
        match self {
            Self::LocalsOp(_) => true,
            _ => false,
        }
    }

    pub fn gc(&self) -> usize {
        match self {
            Self::StackOp(op) => op.gc,
            Self::LocalsOp(op) => op.gc,
        }
    }

    pub fn rw_target(&self) -> RWTarget {
        match self {
            Self::StackOp(_) => RWTarget::Stack,
            Self::LocalsOp(_) => RWTarget::Locals,
        }
    }

    pub fn rw(&self) -> RW {
        match self {
            Self::StackOp(op) => op.rw.clone(),
            Self::LocalsOp(op) => op.rw.clone(),
        }
    }

    pub fn call_index(&self) -> usize {
        match self {
            Self::StackOp(_) => 0,
            Self::LocalsOp(op) => op.call_index,
        }
    }

    pub fn address(&self) -> usize {
        match self {
            Self::StackOp(op) => op.address,
            Self::LocalsOp(op) => op.index,
        }
    }

    pub fn value(&self) -> Value<F> {
        match self {
            Self::StackOp(op) => op.value.clone(),
            Self::LocalsOp(op) => op.value.clone(),
        }
    }
}

// convert RWOperation into a vector of field value
impl<F: FieldExt> From<&RWOperation<F>> for Vec<Option<F>> {
    fn from(rw_op: &RWOperation<F>) -> Vec<Option<F>> {
        let mut field_values = Vec::new();
        field_values.push(Some(F::from_u128(rw_op.gc() as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw_target() as u128)));
        field_values.push(Some(F::from_u128(rw_op.rw() as u128)));
        field_values.push(Some(F::from_u128(rw_op.call_index() as u128)));
        field_values.push(Some(F::from_u128(rw_op.address() as u128)));

        let value = match rw_op.value() {
            Value::Invalid => Some(F::zero()), // todo: how to distinguish with Value::Constant(0)
            _ => rw_op.value().value(),
        };
        field_values.push(value);
        field_values
    }
}

#[derive(Clone, Debug, Default)]
pub struct RWOperations<F: FieldExt>(pub Vec<RWOperation<F>>);

impl<F: FieldExt> From<RWOperations<F>> for (SortedStackOps<F>, SortedLocalsOps<F>) {
    fn from(rw_operations: RWOperations<F>) -> (SortedStackOps<F>, SortedLocalsOps<F>) {
        let mut stack_ops = Vec::new();
        let mut locals_ops = Vec::new();
        rw_operations.0.into_iter().for_each(|op| match op {
            RWOperation::StackOp(stack_op) => stack_ops.push(stack_op),
            RWOperation::LocalsOp(locals_op) => locals_ops.push(locals_op),
        });
        stack_ops.sort();
        locals_ops.sort();
        (SortedStackOps(stack_ops), SortedLocalsOps(locals_ops))
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedStackOps<F: FieldExt>(pub Vec<StackOp<F>>);

// convert SortedStackOps into field values
impl<F: FieldExt> From<&SortedStackOps<F>> for Vec<Vec<Option<F>>> {
    fn from(rw_ops: &SortedStackOps<F>) -> Vec<Vec<Option<F>>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedLocalsOps<F: FieldExt>(pub Vec<LocalsOp<F>>);

// convert SortedLocalsOps into field values
impl<F: FieldExt> From<&SortedLocalsOps<F>> for Vec<Vec<Option<F>>> {
    fn from(rw_ops: &SortedLocalsOps<F>) -> Vec<Vec<Option<F>>> {
        rw_ops.0.iter().map(|op| op.into()).collect()
    }
}
