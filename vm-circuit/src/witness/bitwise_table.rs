// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::file_format::{Bytecode, CompiledModule, CompiledScript};
use std::convert::From;

#[derive(Clone, PartialEq, Debug)]
pub struct BitwiseInfo {
    bytecode: u8,
    value_1: u8,
    value_2: u8,
    result: u8,
}

impl Default for BitwiseInfo {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl BitwiseInfo {
    pub fn new(value_1: u8, value_2: u8, result: u8, bytecode: u8) -> Self {
        BitwiseInfo {
            bytecode,
            value_1,
            value_2,
            result,
        }
    }
}

