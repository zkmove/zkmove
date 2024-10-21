// Copyright (c) zkMove Authors

use crate::static_info::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_binary_format::binary_views::{BinaryIndexedView, FunctionView};
use move_binary_format::file_format::{
    Bytecode, CompiledModule, FunctionDefinitionIndex, SignatureToken,
};
use move_binary_format::file_format_common::instruction_key;
use movelang::type_transition;
use std::collections::BTreeMap;
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct BytecodeInfo {
    pub module_index: u32,
    pub function_index: u16,
    pub pc: u16,
    pub opcode: u8,
    pub aux0: Option<u128>,
    pub aux1: Option<u128>,
}

impl BytecodeInfo {
    pub fn new(
        module: &CompiledModule,
        module_index: u32,
        function_index: u16,
        pc: u16,
        bytecode: Bytecode,
        ty_out: &[SignatureToken],
    ) -> Self {
        let instr = bytecode_to_instruction(module, &bytecode, ty_out);
        BytecodeInfo {
            module_index,
            function_index,
            pc,
            opcode: instr.opcode,
            aux0: instr.aux0,
            aux1: instr.aux1,
        }
    }
}

pub(crate) fn parse_bytecode(
    module_id_mapping: &ModuleIdMapping,
    deps: &[CompiledModule],
) -> BTreeMap<u32, BTreeMap<u16, Vec<BytecodeInfo>>> {
    deps.iter()
        .map(|module| {
            let module_index = module_id_mapping.get_module_index(&module.self_id());
            (module_index, parse_module(module, module_index))
        })
        .collect()
}

fn parse_module(module: &CompiledModule, module_index: u32) -> BTreeMap<u16, Vec<BytecodeInfo>> {
    module
        .function_defs
        .iter()
        .enumerate()
        .filter_map(move |(func_index, func)| {
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
                .expect("generate type transition should not fail");

                let rows = transitions
                    .into_iter()
                    .map(move |(i, transition)| {
                        BytecodeInfo::new(
                            module,
                            module_index,
                            func_index as u16,
                            i,
                            transition.instr,
                            &transition.output,
                        )
                    })
                    .collect::<Vec<_>>();
                Some((func_index as u16, rows))
            } else {
                None
            }
        })
        .collect()
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct Instruction {
    pub(crate) opcode: u8,
    pub(crate) aux0: Option<u128>,
    pub(crate) aux1: Option<u128>,
}

pub const NUM_OF_BYTES_U8: usize = 1;
pub const NUM_OF_BYTES_U16: usize = 2;
pub const NUM_OF_BYTES_U32: usize = 4;
pub const NUM_OF_BYTES_U64: usize = 8;
pub const NUM_OF_BYTES_U128: usize = 16;
pub const NUM_OF_BYTES_U256: usize = 32;

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

/// Convert to opcode, operand1 and operand2
fn bytecode_to_instruction(
    module: &CompiledModule,
    bytecode: &Bytecode,
    ty_out: &[SignatureToken],
) -> Instruction {
    let opcode = instruction_key(bytecode);
    let (aux0, aux1) = match *bytecode {
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
        | Bytecode::Abort => (None, None),
        Bytecode::Add
        | Bytecode::Mul
        | Bytecode::Sub
        | Bytecode::Div
        | Bytecode::Mod
        | Bytecode::Shl
        | Bytecode::Shr => (Some(get_num_bytes(&ty_out[0]) as u128), None),
        Bytecode::LdU8(v) => (Some(v as u128), None),
        Bytecode::LdU16(v) => (Some(v as u128), None),
        Bytecode::LdU32(v) => (Some(v as u128), None),
        Bytecode::LdU64(v) => (Some(v as u128), None),
        Bytecode::LdU128(v) => (Some(v), None),
        Bytecode::LdU256(v) => {
            let lo = u128::from_le_bytes(*v.to_le_bytes().first_chunk::<16>().unwrap());
            let hi = u128::from_le_bytes(*v.to_le_bytes().last_chunk::<16>().unwrap());
            (Some(lo), Some(hi))
        }
        Bytecode::LdConst(v) => (Some(v.0 as u128), None),
        Bytecode::CopyLoc(local_index)
        | Bytecode::MoveLoc(local_index)
        | Bytecode::StLoc(local_index)
        | Bytecode::MutBorrowLoc(local_index)
        | Bytecode::ImmBorrowLoc(local_index) => (Some(local_index as u128), None),
        Bytecode::Branch(code_offset)
        | Bytecode::BrTrue(code_offset)
        | Bytecode::BrFalse(code_offset) => (Some(code_offset as u128), None),
        Bytecode::Call(func_handle_index) => (Some(func_handle_index.0 as u128), None),
        Bytecode::CallGeneric(idx) => (Some(idx.0 as u128), None),
        Bytecode::Pack(sd_idx)
        | Bytecode::Unpack(sd_idx)
        | Bytecode::MoveTo(sd_idx)
        | Bytecode::MoveFrom(sd_idx)
        | Bytecode::Exists(sd_idx)
        | Bytecode::ImmBorrowGlobal(sd_idx)
        | Bytecode::MutBorrowGlobal(sd_idx) => {
            let field_count = module.struct_def_at(sd_idx).declared_field_count().unwrap();
            (Some(sd_idx.0 as u128), Some(field_count as u128))
        }
        Bytecode::PackGeneric(idx)
        | Bytecode::UnpackGeneric(idx)
        | Bytecode::MoveToGeneric(idx)
        | Bytecode::MoveFromGeneric(idx)
        | Bytecode::ExistsGeneric(idx)
        | Bytecode::ImmBorrowGlobalGeneric(idx)
        | Bytecode::MutBorrowGlobalGeneric(idx) => {
            let field_count = module
                .struct_def_at(module.struct_instantiation_at(idx).def)
                .declared_field_count()
                .unwrap();
            (Some(idx.0 as u128), Some(field_count as u128))
        }
        Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
            (Some(module.field_handle_at(fh_idx).field as u128), None)
        }
        Bytecode::ImmBorrowFieldGeneric(idx) | Bytecode::MutBorrowFieldGeneric(idx) => {
            (Some(idx.0 as u128), None)
        }
        Bytecode::VecImmBorrow(idx)
        | Bytecode::VecMutBorrow(idx)
        | Bytecode::VecLen(idx)
        | Bytecode::VecPopBack(idx)
        | Bytecode::VecPushBack(idx)
        | Bytecode::VecSwap(idx) => (Some(idx.0 as u128), None),
        Bytecode::VecPack(idx, num) | Bytecode::VecUnpack(idx, num) => {
            (Some(idx.0 as u128), Some(num as u128))
        }
        Bytecode::Nop => (None, None),
    };
    Instruction { opcode, aux0, aux1 }
}

#[cfg(test)]
mod tests {
    use crate::static_info::bytecode::{parse_module, BytecodeInfo};
    use move_binary_format::file_format::{
        empty_module, Bytecode, CodeUnit, CompiledModule, FunctionDefinition, FunctionHandle,
        FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex, SignatureIndex, Visibility,
    };
    use move_binary_format::file_format_common::Opcodes;
    use move_core_types::identifier::Identifier;

    /// A dummy compiled module:
    ///
    /// module {
    ///    func1() {
    ///    }
    ///    func2() {
    ///    }
    /// }
    ///
    fn dummy_module() -> CompiledModule {
        let mut m = empty_module();

        // func1
        m.identifiers
            .push(Identifier::new("func1".to_string()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(m.identifiers.len() as u16),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
            access_specifiers: None,
        });
        m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    Bytecode::LdU64(1u64),
                    Bytecode::LdU64(2u64),
                    Bytecode::Add,
                    Bytecode::Pop,
                    Bytecode::Ret,
                ],
            }),
        });

        // func2
        m.identifiers
            .push(Identifier::new("func2".to_string()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(m.identifiers.len() as u16),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
            access_specifiers: None,
        });
        m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(1),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    Bytecode::LdU64(1u64),
                    Bytecode::LdU64(2u64),
                    Bytecode::Sub,
                    Bytecode::Pop,
                    Bytecode::Ret,
                ],
            }),
        });
        m
    }

    #[test]
    fn test_bytecode_table() {
        logger::init_for_test();

        let module = dummy_module();
        let bytecodes = parse_module(&module, 0)
            .into_iter()
            .flat_map(|v| v.1)
            .collect::<Vec<_>>();

        let expected_bytecode_table = vec![
            BytecodeInfo {
                module_index: 0,
                function_index: 0,
                pc: 0,
                opcode: Opcodes::LD_U64 as u8,
                aux0: Some(2),
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 0,
                pc: 1,
                opcode: Opcodes::LD_U64 as u8,
                aux0: Some(2),
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 0,
                pc: 2,
                opcode: Opcodes::ADD as u8,
                aux0: None,
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 0,
                pc: 3,
                opcode: Opcodes::POP as u8,
                aux0: None,
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 0,
                pc: 4,
                opcode: Opcodes::RET as u8,
                aux0: None,
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 1,
                pc: 0,
                opcode: Opcodes::LD_U64 as u8,
                aux0: Some(1),
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 1,
                pc: 1,
                opcode: Opcodes::LD_U64 as u8,
                aux0: Some(2),
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 1,
                pc: 2,
                opcode: Opcodes::SUB as u8,
                aux0: None,
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 1,
                pc: 3,
                opcode: Opcodes::POP as u8,
                aux0: None,
                aux1: None,
            },
            BytecodeInfo {
                module_index: 0,
                function_index: 1,
                pc: 4,
                opcode: Opcodes::RET as u8,
                aux0: None,
                aux1: None,
            },
        ];

        assert_eq!(bytecodes, expected_bytecode_table, "result is not expected");
    }
}
