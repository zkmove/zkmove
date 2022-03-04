// Copyright (c) zkMove Authors

use crate::value::Value;
use halo2::arithmetic::FieldExt;
use move_binary_format::file_format::Bytecode;

#[derive(Debug)]
pub struct ExecutionStep {
    pub bytecode: Bytecode,
    pub pc: u16,
    pub stack_size: usize,
    pub call_index: usize,
    pub gc: usize, // global counter for stack, locals, state accesses
}

#[derive(Debug)]
pub enum RW {
    READ,
    WRITE,
}

#[derive(Debug)]
pub struct LocalsOp<F: FieldExt> {
    pub call_index: usize,
    pub index: usize,
    pub value: Value<F>,
    pub rw: RW,
}

#[derive(Debug)]
pub struct StackOp<F: FieldExt> {
    pub address: usize,
    pub value: Value<F>,
    pub rw: RW,
}

#[derive(Debug)]
pub enum RWOperation<F: FieldExt> {
    LocalsOp(LocalsOp<F>),
    StackOp(StackOp<F>),
}
