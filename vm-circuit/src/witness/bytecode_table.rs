// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use move_binary_format::file_format::{Bytecode, CompiledModule, CompiledScript};
use movelang::utility::convert_u256_to_field;
use std::convert::From;
use types::Field;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BytecodeInfo {
    module_index: u16,
    function_index: u16,
    pc: u16,
    bytecode: Bytecode,
}

impl Default for BytecodeInfo {
    fn default() -> Self {
        Self::new(0, 0, 0, Bytecode::Nop)
    }
}

impl BytecodeInfo {
    pub fn new(module_index: u16, function_index: u16, pc: u16, bytecode: Bytecode) -> Self {
        BytecodeInfo {
            module_index,
            function_index,
            pc,
            bytecode,
        }
    }
}

pub fn convert_bytecode_to_fields<F: Field>(bytecode: Bytecode) -> (F, F) {
    match bytecode {
        Bytecode::LdU8(v) => (
            F::from_u128(Opcode::LdU8.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU16(v) => (
            F::from_u128(Opcode::LdU16.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU32(v) => (
            F::from_u128(Opcode::LdU32.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU64(v) => (
            F::from_u128(Opcode::LdU64.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU128(v) => (
            F::from_u128(Opcode::LdU128.index() as u128),
            F::from_u128(v),
        ),
        // LdU256 is processed at another function
        // Bytecode::LdU256(v) => (
        // ),
        Bytecode::LdConst(v) => (
            F::from_u128(Opcode::LdConst.index() as u128),
            F::from_u128(v.0 as u128),
        ),
        Bytecode::CastU8 => (F::from_u128(Opcode::CastU8.index() as u128), F::ZERO),
        Bytecode::CastU16 => (F::from_u128(Opcode::CastU16.index() as u128), F::ZERO),
        Bytecode::CastU32 => (F::from_u128(Opcode::CastU32.index() as u128), F::ZERO),
        Bytecode::CastU64 => (F::from_u128(Opcode::CastU64.index() as u128), F::ZERO),
        Bytecode::CastU128 => (F::from_u128(Opcode::CastU128.index() as u128), F::ZERO),
        Bytecode::CastU256 => (F::from_u128(Opcode::CastU256.index() as u128), F::ZERO),
        Bytecode::Pop => (F::from_u128(Opcode::Pop.index() as u128), F::ZERO),
        Bytecode::Ret => (F::from_u128(Opcode::Ret.index() as u128), F::ZERO),
        Bytecode::Add => (F::from_u128(Opcode::Add.index() as u128), F::ZERO),
        Bytecode::Mul => (F::from_u128(Opcode::Mul.index() as u128), F::ZERO),
        Bytecode::CopyLoc(local_index) => (
            F::from_u128(Opcode::CopyLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::Sub => (F::from_u128(Opcode::Sub.index() as u128), F::ZERO),
        Bytecode::Div => (F::from_u128(Opcode::Div.index() as u128), F::ZERO),
        Bytecode::Mod => (F::from_u128(Opcode::Mod.index() as u128), F::ZERO),
        Bytecode::LdTrue => (F::from_u128(Opcode::LdTrue.index() as u128), F::ZERO),
        Bytecode::LdFalse => (F::from_u128(Opcode::LdFalse.index() as u128), F::ZERO),
        Bytecode::Eq => (F::from_u128(Opcode::Eq.index() as u128), F::ZERO),
        Bytecode::Neq => (F::from_u128(Opcode::Neq.index() as u128), F::ZERO),
        Bytecode::Le => (F::from_u128(Opcode::Le.index() as u128), F::ZERO),
        Bytecode::Lt => (F::from_u128(Opcode::Lt.index() as u128), F::ZERO),
        Bytecode::Ge => (F::from_u128(Opcode::Ge.index() as u128), F::ZERO),
        Bytecode::Gt => (F::from_u128(Opcode::Gt.index() as u128), F::ZERO),
        Bytecode::Shl => (F::from_u128(Opcode::Shl.index() as u128), F::ZERO),
        Bytecode::Shr => (F::from_u128(Opcode::Shr.index() as u128), F::ZERO),
        Bytecode::BitAnd => (F::from_u128(Opcode::BitAnd.index() as u128), F::ZERO),
        Bytecode::BitOr => (F::from_u128(Opcode::BitOr.index() as u128), F::ZERO),
        Bytecode::Xor => (F::from_u128(Opcode::Xor.index() as u128), F::ZERO),
        Bytecode::And => (F::from_u128(Opcode::And.index() as u128), F::ZERO),
        Bytecode::Or => (F::from_u128(Opcode::Or.index() as u128), F::ZERO),
        Bytecode::Not => (F::from_u128(Opcode::Not.index() as u128), F::ZERO),
        Bytecode::MoveLoc(local_index) => (
            F::from_u128(Opcode::MoveLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::StLoc(local_index) => (
            F::from_u128(Opcode::StLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::Branch(code_offset) => (
            F::from_u128(Opcode::Branch.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::BrTrue(code_offset) => (
            F::from_u128(Opcode::BrTrue.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::BrFalse(code_offset) => (
            F::from_u128(Opcode::BrFalse.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::Call(func_handle_index) => (
            F::from_u128(Opcode::Call.index() as u128),
            F::from_u128(func_handle_index.0 as u128),
        ),
        Bytecode::Abort => (F::from_u128(Opcode::Abort.index() as u128), F::ZERO),
        Bytecode::Pack(struct_def_index) => (
            F::from_u128(Opcode::Pack.index() as u128),
            F::from_u128(struct_def_index.0 as u128),
        ),
        Bytecode::Unpack(struct_def_index) => (
            F::from_u128(Opcode::Unpack.index() as u128),
            F::from_u128(struct_def_index.0 as u128),
        ),
        Bytecode::MutBorrowLoc(local_index) => (
            F::from_u128(Opcode::MutBorrowLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::ImmBorrowLoc(local_index) => (
            F::from_u128(Opcode::ImmBorrowLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::ReadRef => (F::from_u128(Opcode::ReadRef.index() as u128), F::ZERO),
        Bytecode::WriteRef => (F::from_u128(Opcode::WriteRef.index() as u128), F::ZERO),
        Bytecode::FreezeRef => (F::from_u128(Opcode::FreezeRef.index() as u128), F::ZERO),
        Bytecode::ImmBorrowField(fh_idx) => (
            F::from_u128(Opcode::ImmBorrowField.index() as u128),
            F::from_u128(fh_idx.0 as u128),
        ),
        Bytecode::MutBorrowField(fh_idx) => (
            F::from_u128(Opcode::MutBorrowField.index() as u128),
            F::from_u128(fh_idx.0 as u128),
        ),
        Bytecode::MoveTo(sd_idx) => (
            F::from_u128(Opcode::MoveTo.index() as u128),
            F::from_u128(sd_idx.0 as u128),
        ),
        Bytecode::MoveFrom(sd_idx) => (
            F::from_u128(Opcode::MoveFrom.index() as u128),
            F::from_u128(sd_idx.0 as u128),
        ),
        Bytecode::Exists(sd_idx) => (
            F::from_u128(Opcode::Exists.index() as u128),
            F::from_u128(sd_idx.0 as u128),
        ),
        Bytecode::ImmBorrowGlobal(sd_idx) => (
            F::from_u128(Opcode::ImmBorrowGlobal.index() as u128),
            F::from_u128(sd_idx.0 as u128),
        ),
        Bytecode::MutBorrowGlobal(sd_idx) => (
            F::from_u128(Opcode::MutBorrowGlobal.index() as u128),
            F::from_u128(sd_idx.0 as u128),
        ),
        Bytecode::CallGeneric(idx) => (
            F::from_u128(Opcode::CallGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::ExistsGeneric(idx) => (
            F::from_u128(Opcode::ExistsGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::PackGeneric(idx) => (
            F::from_u128(Opcode::PackGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::UnpackGeneric(idx) => (
            F::from_u128(Opcode::UnpackGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::ImmBorrowFieldGeneric(idx) => (
            F::from_u128(Opcode::ImmBorrowFieldGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::MutBorrowFieldGeneric(idx) => (
            F::from_u128(Opcode::MutBorrowFieldGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::MoveFromGeneric(idx) => (
            F::from_u128(Opcode::MoveFromGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::MoveToGeneric(idx) => (
            F::from_u128(Opcode::MoveToGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::ImmBorrowGlobalGeneric(idx) => (
            F::from_u128(Opcode::ImmBorrowGlobalGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::MutBorrowGlobalGeneric(idx) => (
            F::from_u128(Opcode::MutBorrowGlobalGeneric.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecImmBorrow(idx) => (
            F::from_u128(Opcode::VecImmBorrow.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecMutBorrow(idx) => (
            F::from_u128(Opcode::VecMutBorrow.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecLen(idx) => (
            F::from_u128(Opcode::VecLen.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        // todo: handle the second operand
        Bytecode::VecPack(idx, _) => (
            F::from_u128(Opcode::VecPack.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecPopBack(idx) => (
            F::from_u128(Opcode::VecPopBack.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecPushBack(idx) => (
            F::from_u128(Opcode::VecPushBack.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        Bytecode::VecSwap(idx) => (
            F::from_u128(Opcode::VecSwap.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        // todo: handle the second operand
        Bytecode::VecUnpack(idx, _) => (
            F::from_u128(Opcode::VecUnpack.index() as u128),
            F::from_u128(idx.0 as u128),
        ),
        _ => unimplemented!("{:?}", bytecode),
    }
}

pub fn convert_bytecode_to_fields_operand2<F: Field>(bytecode: Bytecode) -> (F, F, F) {
    match bytecode {
        Bytecode::LdU256(v) => {
            let opcode = F::from_u128(Opcode::LdU256.index() as u128);
            let f = convert_u256_to_field::<F>(&v);
            (opcode, f[0], f[1])
        }
        _ => unimplemented!("{:?}", bytecode),
    }
}

// convert BytecodeInfo into a vector of field values
impl<F: Field> From<&BytecodeInfo> for Vec<F> {
    fn from(bytecode_info: &BytecodeInfo) -> Vec<F> {
        let mut field_values = vec![
            F::from_u128(bytecode_info.module_index as u128),
            F::from_u128(bytecode_info.function_index as u128),
            F::from_u128(bytecode_info.pc as u128),
        ];

        // most of opcode need to insert reserved value for upper field
        let bc = bytecode_info.bytecode.clone();
        match bytecode_info.bytecode.clone() {
            Bytecode::LdU256(_) => {
                let (opcode, operand2, operand) = convert_bytecode_to_fields_operand2(bc);
                field_values.push(opcode);
                field_values.push(operand2);
                field_values.push(operand);
            }
            _ => {
                let (opcode, operand) = convert_bytecode_to_fields(bc);
                field_values.push(opcode);
                field_values.push(F::ZERO);
                field_values.push(operand);
            }
        }

        field_values
    }
}

#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct BytecodeTable(Vec<BytecodeInfo>);

impl BytecodeTable {
    pub fn new(bytecodes: Vec<BytecodeInfo>) -> Self {
        Self(bytecodes)
    }
    pub fn as_inner(&self) -> &Vec<BytecodeInfo> {
        &self.0
    }
    pub fn into_inner(self) -> Vec<BytecodeInfo> {
        self.0
    }
}

// convert BytecodeTable into a vector of vector of field values
impl<F: Field> From<&BytecodeTable> for Vec<Vec<F>> {
    fn from(bytecode_table: &BytecodeTable) -> Vec<Vec<F>> {
        bytecode_table
            .0
            .iter()
            .map(|bytecode_info| bytecode_info.into())
            .collect()
    }
}

impl From<CompiledScript> for BytecodeTable {
    fn from(script: CompiledScript) -> BytecodeTable {
        BytecodeTable(
            script
                .code
                .code
                .iter()
                .enumerate()
                .map(|(i, bytecode)| {
                    BytecodeInfo::new(
                        0, /* module id of a script is always 0 */
                        0,
                        i as u16,
                        bytecode.clone(),
                    )
                })
                .collect(),
        )
    }
}

impl From<Vec<CompiledModule>> for BytecodeTable {
    fn from(modules: Vec<CompiledModule>) -> BytecodeTable {
        let mut bytecodes = Vec::new();
        for (index, module) in modules.iter().enumerate() {
            let module_index = index + 1;
            for func_def in module.function_defs.iter() {
                if let Some(code_unit) = func_def.code.clone() {
                    let mut func_bytecodes = code_unit
                        .code
                        .iter()
                        .enumerate()
                        .map(|(i, bytecode)| {
                            BytecodeInfo::new(
                                module_index as u16,
                                func_def.function.0, // TODO: change to function def index
                                i as u16,
                                bytecode.clone(),
                            )
                        })
                        .collect();
                    bytecodes.append(&mut func_bytecodes);
                }
            }
        }
        BytecodeTable(bytecodes)
    }
}

impl From<(CompiledScript, Vec<CompiledModule>)> for BytecodeTable {
    fn from((script, modules): (CompiledScript, Vec<CompiledModule>)) -> BytecodeTable {
        let script_bytecodes = BytecodeTable::from(script);
        let modules_bytecodes = BytecodeTable::from(modules);
        let mut bytecodes = Vec::new();
        bytecodes.append(&mut script_bytecodes.into_inner());
        bytecodes.append(&mut modules_bytecodes.into_inner());
        BytecodeTable(bytecodes)
    }
}

#[cfg(test)]
mod tests {
    use crate::witness::bytecode_table::{BytecodeInfo, BytecodeTable};
    use error::VmResult;
    use move_binary_format::file_format::{
        empty_module, empty_script, Bytecode, CodeUnit, CompiledModule, CompiledScript,
        FunctionDefinition, FunctionHandle, FunctionHandleIndex, IdentifierIndex,
        ModuleHandleIndex, SignatureIndex, Visibility,
    };
    use move_core_types::identifier::Identifier;

    // module {
    //     foo() {
    //     }
    // }
    fn test_module() -> CompiledModule {
        let mut m = empty_module();

        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(m.identifiers.len() as u16),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.identifiers
            .push(Identifier::new("foo".to_string()).unwrap());

        m.function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::Ret],
            }),
        });
        m
    }

    fn test_script() -> CompiledScript {
        let mut script = empty_script();
        script.code.code = vec![
            Bytecode::LdU64(1u64),
            Bytecode::LdU64(2u64),
            Bytecode::Add,
            Bytecode::Pop,
            Bytecode::Ret,
        ];
        script
    }

    #[test]
    fn test_bytecode_table() -> VmResult<()> {
        logger::init_for_test();

        let script = test_script();
        let module = test_module();
        let bytecodes = BytecodeTable::from((script, vec![module]));

        let expected_bytecode_table = BytecodeTable(vec![
            BytecodeInfo::new(0, 0, 0, Bytecode::LdU64(1u64)),
            BytecodeInfo::new(0, 0, 1, Bytecode::LdU64(2u64)),
            BytecodeInfo::new(0, 0, 2, Bytecode::Add),
            BytecodeInfo::new(0, 0, 3, Bytecode::Pop),
            BytecodeInfo::new(0, 0, 4, Bytecode::Ret),
            BytecodeInfo::new(1, 0, 0, Bytecode::Ret),
        ]);

        assert_eq!(bytecodes, expected_bytecode_table, "result is not expected");
        Ok(())
    }
}
