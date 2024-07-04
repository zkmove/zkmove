// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::witness::utils::convert_u256_to_fe_pair;
use crate::witness::utils::ModuleIdMapping;
use move_binary_format::file_format::Bytecode;
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;
use std::convert::From;
use types::Field;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BytecodeTableRow {
    module_index: usize,
    function_index: usize,
    pc: u16,
    bytecode: Bytecode,
}

impl BytecodeTableRow {
    pub fn new(module_index: usize, function_index: usize, pc: u16, bytecode: Bytecode) -> Self {
        BytecodeTableRow {
            module_index,
            function_index,
            pc,
            bytecode,
        }
    }

    pub fn to_fe<F: Field>(&self) -> Vec<F> {
        let mut field_elements = vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.pc as u128),
        ];

        let fes = Self::bytecode_to_fe(self.bytecode.clone());
        field_elements.append(&mut fes.to_vec());
        field_elements
    }

    /// Convert opcode, operand1 and operand2 of given bytecode into field elements
    fn bytecode_to_fe<F: Field>(bytecode: Bytecode) -> [F; 3] {
        let fe = F::from(Opcode::from(bytecode.clone()).index() as u64);
        match bytecode {
            Bytecode::CastU8
            | Bytecode::CastU16
            | Bytecode::CastU32
            | Bytecode::CastU64
            | Bytecode::CastU128
            | Bytecode::CastU256
            | Bytecode::Pop
            | Bytecode::Ret
            | Bytecode::Add
            | Bytecode::Mul
            | Bytecode::Sub
            | Bytecode::Div
            | Bytecode::Mod
            | Bytecode::LdTrue
            | Bytecode::LdFalse
            | Bytecode::Eq
            | Bytecode::Neq
            | Bytecode::Le
            | Bytecode::Lt
            | Bytecode::Ge
            | Bytecode::Gt
            | Bytecode::Shl
            | Bytecode::Shr
            | Bytecode::BitAnd
            | Bytecode::BitOr
            | Bytecode::Xor
            | Bytecode::And
            | Bytecode::Or
            | Bytecode::Not
            | Bytecode::ReadRef
            | Bytecode::WriteRef
            | Bytecode::FreezeRef
            | Bytecode::Abort => [fe, F::ZERO, F::ZERO],
            Bytecode::LdU8(v) => [fe, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU16(v) => [fe, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU32(v) => [fe, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU64(v) => [fe, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU128(v) => [fe, F::from_u128(v), F::ZERO],
            Bytecode::LdU256(v) => {
                let (lo, hi) = convert_u256_to_fe_pair::<F>(v);
                [fe, lo, hi]
            }
            Bytecode::LdConst(v) => [fe, F::from_u128(v.0 as u128), F::ZERO],
            Bytecode::CopyLoc(local_index)
            | Bytecode::MoveLoc(local_index)
            | Bytecode::StLoc(local_index)
            | Bytecode::MutBorrowLoc(local_index)
            | Bytecode::ImmBorrowLoc(local_index) => [fe, F::from(local_index as u64), F::ZERO],
            Bytecode::Branch(code_offset)
            | Bytecode::BrTrue(code_offset)
            | Bytecode::BrFalse(code_offset) => [fe, F::from(code_offset as u64), F::ZERO],
            Bytecode::Call(func_handle_index) => [fe, F::from(func_handle_index.0 as u64), F::ZERO],
            Bytecode::CallGeneric(idx) => [fe, F::from(idx.0 as u64), F::ZERO],
            Bytecode::Pack(sd_idx)
            | Bytecode::Unpack(sd_idx)
            | Bytecode::MoveTo(sd_idx)
            | Bytecode::MoveFrom(sd_idx)
            | Bytecode::Exists(sd_idx)
            | Bytecode::ImmBorrowGlobal(sd_idx)
            | Bytecode::MutBorrowGlobal(sd_idx) => [fe, F::from(sd_idx.0 as u64), F::ZERO],
            Bytecode::PackGeneric(idx)
            | Bytecode::UnpackGeneric(idx)
            | Bytecode::MoveToGeneric(idx)
            | Bytecode::MoveFromGeneric(idx)
            | Bytecode::ExistsGeneric(idx)
            | Bytecode::ImmBorrowGlobalGeneric(idx)
            | Bytecode::MutBorrowGlobalGeneric(idx) => [fe, F::from(idx.0 as u64), F::ZERO],
            Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
                [fe, F::from(fh_idx.0 as u64), F::ZERO]
            }
            Bytecode::ImmBorrowFieldGeneric(idx) | Bytecode::MutBorrowFieldGeneric(idx) => {
                [fe, F::from(idx.0 as u64), F::ZERO]
            }
            Bytecode::VecImmBorrow(idx)
            | Bytecode::VecMutBorrow(idx)
            | Bytecode::VecLen(idx)
            | Bytecode::VecPopBack(idx)
            | Bytecode::VecPushBack(idx)
            | Bytecode::VecSwap(idx) => [fe, F::from(idx.0 as u64), F::ZERO],
            Bytecode::VecPack(idx, num) | Bytecode::VecUnpack(idx, num) => {
                [fe, F::from(idx.0 as u64), F::from(num)]
            }
            _ => unimplemented!("{:?}", bytecode),
        }
    }
}

/// parse bytecode in the transitive dependencies of `module_id`
pub fn parse_bytecode(module_id: &ModuleId, package: &CompiledPackage) -> Vec<BytecodeTableRow> {
    let modules = package.all_modules_map();
    let deps = modules.get_transitive_dependencies(module_id).unwrap();
    let mapping = ModuleIdMapping::construct(package);
    let mut bytecodes = Vec::new();

    deps.iter().for_each(|module| {
        let module_index = mapping.module_index(module.self_id());
        for (index, func_def) in module.function_defs.iter().enumerate() {
            if let Some(code_unit) = func_def.code.clone() {
                let mut bytecode = code_unit
                    .code
                    .iter()
                    .enumerate()
                    .map(|(i, bytecode)| BytecodeTableRow {
                        module_index,
                        function_index: index,
                        pc: i as u16,
                        bytecode: bytecode.clone(),
                    })
                    .collect();
                bytecodes.append(&mut bytecode);
            }
        }
    });
    bytecodes
}
