// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::witness::utils::convert_u256_to_fe_pair;
use crate::witness::utils::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_binary_format::binary_views::{BinaryIndexedView, FunctionView};
use move_binary_format::file_format::{Bytecode, FunctionDefinitionIndex, SignatureToken};
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;
use movelang::type_transition;
use std::convert::From;
use types::Field;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BytecodeTableRow {
    module_index: usize,
    function_index: usize,
    pc: u16,
    bytecode: Bytecode,
    /// types that outputted by the bytecode
    ty_out: Vec<SignatureToken>,
}

impl BytecodeTableRow {
    pub fn to_fe<F: Field>(&self) -> Vec<F> {
        let mut field_elements = vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.pc as u128),
        ];

        let fes = Self::bytecode_to_fe(&self.bytecode, &self.ty_out);
        field_elements.append(&mut fes.to_vec());
        field_elements
    }

    /// Convert opcode, operand1 and operand2 of given bytecode into field elements
    fn bytecode_to_fe<F: Field>(bytecode: &Bytecode, ty_out: &Vec<SignatureToken>) -> [F; 3] {
        let fe_opcode = F::from(Opcode::from(bytecode.clone()).index() as u64);
        match *bytecode {
            Bytecode::CastU8
            | Bytecode::CastU16
            | Bytecode::CastU32
            | Bytecode::CastU64
            | Bytecode::CastU128
            | Bytecode::CastU256
            | Bytecode::Pop
            | Bytecode::Ret
            | Bytecode::LdTrue
            | Bytecode::LdFalse
            | Bytecode::Eq
            | Bytecode::Neq
            | Bytecode::Le
            | Bytecode::Lt
            | Bytecode::Ge
            | Bytecode::Gt
            | Bytecode::BitAnd
            | Bytecode::BitOr
            | Bytecode::Xor
            | Bytecode::And
            | Bytecode::Or
            | Bytecode::Not
            | Bytecode::ReadRef
            | Bytecode::WriteRef
            | Bytecode::FreezeRef
            | Bytecode::Abort => [fe_opcode, F::ZERO, F::ZERO],
            Bytecode::Add
            | Bytecode::Mul
            | Bytecode::Sub
            | Bytecode::Div
            | Bytecode::Mod
            | Bytecode::Shl
            | Bytecode::Shr => [
                fe_opcode,
                F::from_u128(get_num_bytes(&ty_out[0]) as u128),
                F::ZERO,
            ],
            Bytecode::LdU8(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU16(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU32(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU64(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
            Bytecode::LdU128(v) => [fe_opcode, F::from_u128(v), F::ZERO],
            Bytecode::LdU256(v) => {
                let (lo, hi) = convert_u256_to_fe_pair::<F>(v);
                [fe_opcode, lo, hi]
            }
            Bytecode::LdConst(v) => [fe_opcode, F::from_u128(v.0 as u128), F::ZERO],
            Bytecode::CopyLoc(local_index)
            | Bytecode::MoveLoc(local_index)
            | Bytecode::StLoc(local_index)
            | Bytecode::MutBorrowLoc(local_index)
            | Bytecode::ImmBorrowLoc(local_index) => {
                [fe_opcode, F::from(local_index as u64), F::ZERO]
            }
            Bytecode::Branch(code_offset)
            | Bytecode::BrTrue(code_offset)
            | Bytecode::BrFalse(code_offset) => [fe_opcode, F::from(code_offset as u64), F::ZERO],
            Bytecode::Call(func_handle_index) => {
                [fe_opcode, F::from(func_handle_index.0 as u64), F::ZERO]
            }
            Bytecode::CallGeneric(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
            Bytecode::Pack(sd_idx)
            | Bytecode::Unpack(sd_idx)
            | Bytecode::MoveTo(sd_idx)
            | Bytecode::MoveFrom(sd_idx)
            | Bytecode::Exists(sd_idx)
            | Bytecode::ImmBorrowGlobal(sd_idx)
            | Bytecode::MutBorrowGlobal(sd_idx) => [fe_opcode, F::from(sd_idx.0 as u64), F::ZERO],
            Bytecode::PackGeneric(idx)
            | Bytecode::UnpackGeneric(idx)
            | Bytecode::MoveToGeneric(idx)
            | Bytecode::MoveFromGeneric(idx)
            | Bytecode::ExistsGeneric(idx)
            | Bytecode::ImmBorrowGlobalGeneric(idx)
            | Bytecode::MutBorrowGlobalGeneric(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
            Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
                [fe_opcode, F::from(fh_idx.0 as u64), F::ZERO]
            }
            Bytecode::ImmBorrowFieldGeneric(idx) | Bytecode::MutBorrowFieldGeneric(idx) => {
                [fe_opcode, F::from(idx.0 as u64), F::ZERO]
            }
            Bytecode::VecImmBorrow(idx)
            | Bytecode::VecMutBorrow(idx)
            | Bytecode::VecLen(idx)
            | Bytecode::VecPopBack(idx)
            | Bytecode::VecPushBack(idx)
            | Bytecode::VecSwap(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
            Bytecode::VecPack(idx, num) | Bytecode::VecUnpack(idx, num) => {
                [fe_opcode, F::from(idx.0 as u64), F::from(num)]
            }
            _ => unimplemented!("{:?}", bytecode),
        }
    }
}

/// parse bytecode in the transitive dependencies of `module_id`
pub fn parse_bytecode(module_id: &ModuleId, package: &CompiledPackage) -> Vec<BytecodeTableRow> {
    let modules = package.all_modules_map();
    let deps = modules.get_transitive_dependencies(module_id).unwrap();
    let module_id_mapping = ModuleIdMapping::construct(package);
    deps.iter()
        .flat_map(|module| {
            module
                .function_defs
                .iter()
                .enumerate()
                .filter_map(|(func_index, func)| {
                    if let Some(code) = func.code.as_ref() {
                        let fh = module.function_handle_at(func.function);
                        let transitions = type_transition::generate(
                            &BinaryIndexedView::Module(module),
                            &FunctionView::function(
                                module,
                                FunctionDefinitionIndex(func_index as u16),
                                code,
                                fh,
                            ),
                        )
                        .expect("generate type transition success.");
                        let module_index = module_id_mapping.get_module_index(module.self_id());
                        Some((module_index, func_index, transitions))
                    } else {
                        None
                    }
                })
        })
        .flat_map(|(module_index, func_index, type_transitions)| {
            type_transitions
                .into_iter()
                .map(move |(i, transition)| BytecodeTableRow {
                    module_index,
                    function_index: func_index,
                    pc: i as u16,
                    bytecode: transition.instr,
                    ty_out: transition.output,
                })
        })
        .collect()
}

fn get_num_bytes(s: &SignatureToken) -> usize {
    match s {
        SignatureToken::U8 => NUM_OF_BYTES_U8,
        SignatureToken::U16 => NUM_OF_BYTES_U16,
        SignatureToken::U32 => NUM_OF_BYTES_U32,
        SignatureToken::U64 => NUM_OF_BYTES_U64,
        SignatureToken::U128 => NUM_OF_BYTES_U128,
        SignatureToken::U256 => NUM_OF_BYTES_U256,
        _ => unreachable!(),
    }
}
