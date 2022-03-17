// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::Opcode;
use crate::value::Value;
use halo2::arithmetic::FieldExt;
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStep {
    pub opcode: Opcode,
    pub pc: u16,
    pub stack_size: usize,
    pub call_index: usize,
    pub gc: usize, // global counter for stack, locals, state accesses
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RW {
    READ,
    WRITE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalsOp<F: FieldExt> {
    pub call_index: usize,
    pub index: usize,
    pub value: Value<F>,
    pub rw: RW,
    pub gc: usize,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackOp<F: FieldExt> {
    pub address: usize,
    pub value: Value<F>,
    pub rw: RW,
    pub gc: usize,
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

    pub fn rw_value(&self) -> Value<F> {
        match self {
            Self::StackOp(op) => op.value.clone(),
            Self::LocalsOp(op) => op.value.clone(),
        }
    }

    pub fn rw(&self) -> RW {
        match self {
            Self::StackOp(op) => op.rw.clone(),
            Self::LocalsOp(op) => op.rw.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RWLookUpTable<F: FieldExt>(pub Vec<RWOperation<F>>);

impl<F: FieldExt> From<RWLookUpTable<F>> for (StackLookUpTable<F>, LocalsLookUpTable<F>) {
    fn from(rw_table: RWLookUpTable<F>) -> (StackLookUpTable<F>, LocalsLookUpTable<F>) {
        let mut stack_ops = Vec::new();
        let mut locals_ops = Vec::new();
        rw_table.0.into_iter().for_each(|op| match op {
            RWOperation::StackOp(stack_op) => stack_ops.push(stack_op),
            RWOperation::LocalsOp(locals_op) => locals_ops.push(locals_op),
        });
        stack_ops.sort();
        locals_ops.sort();
        (StackLookUpTable(stack_ops), LocalsLookUpTable(locals_ops))
    }
}

#[derive(Clone, Debug, Default)]
pub struct StackLookUpTable<F: FieldExt>(pub Vec<StackOp<F>>);

#[derive(Clone, Debug, Default)]
pub struct LocalsLookUpTable<F: FieldExt>(pub Vec<LocalsOp<F>>);

#[derive(Clone, Default)]
pub struct CircuitInputs<F: FieldExt> {
    pub exec_steps: Vec<ExecutionStep>,
    pub rw_lookup_table: RWLookUpTable<F>,
    pub stack_lookup_table: StackLookUpTable<F>,
    pub locals_lookup_table: LocalsLookUpTable<F>,
}

impl<F: FieldExt> CircuitInputs<F> {
    pub fn new(exec_steps: Vec<ExecutionStep>, rw_lookup_table: RWLookUpTable<F>) -> Self {
        let (stack_lookup_table, locals_lookup_table) = rw_lookup_table.clone().into();
        CircuitInputs {
            exec_steps,
            rw_lookup_table,
            stack_lookup_table,
            locals_lookup_table,
        }
    }
}

impl<F: FieldExt> fmt::Debug for CircuitInputs<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\n")?;
        write!(f, "Read/Write operation lookup table:\n")?;
        self.rw_lookup_table.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        write!(f, "\n")?;
        write!(f, "Stack operation lookup table:\n")?;
        self.stack_lookup_table.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        write!(f, "\n")?;
        write!(f, "Locals operation lookup table:\n")?;
        self.locals_lookup_table.0.iter().for_each(|op| {
            write!(f, "{:?}\n", op).unwrap();
        });
        Ok(())
    }
}
