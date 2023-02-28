// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::file_format::{Bytecode, CompiledModule, CompiledScript};
use std::convert::From;
use std::ops::{Deref, DerefMut};

#[derive(Clone, PartialEq, Debug)]
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

pub fn convert_bytecode_to_fields<F: FieldExt>(bytecode: Bytecode) -> (F, F) {
    match bytecode {
        Bytecode::LdU8(v) => (
            F::from_u128(Opcode::LdU8.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU64(v) => (
            F::from_u128(Opcode::LdU64.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU128(v) => (
            F::from_u128(Opcode::LdU128.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::CastU8 => (F::from_u128(Opcode::CastU8.index() as u128), F::zero()),
        Bytecode::CastU64 => (F::from_u128(Opcode::CastU64.index() as u128), F::zero()),
        Bytecode::CastU128 => (F::from_u128(Opcode::CastU128.index() as u128), F::zero()),
        Bytecode::Pop => (F::from_u128(Opcode::Pop.index() as u128), F::zero()),
        Bytecode::Ret => (F::from_u128(Opcode::Ret.index() as u128), F::zero()),
        Bytecode::Add => (F::from_u128(Opcode::Add.index() as u128), F::zero()),
        Bytecode::Mul => (F::from_u128(Opcode::Mul.index() as u128), F::zero()),
        Bytecode::CopyLoc(local_index) => (
            F::from_u128(Opcode::CopyLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::Sub => (F::from_u128(Opcode::Sub.index() as u128), F::zero()),
        Bytecode::Div => (F::from_u128(Opcode::Div.index() as u128), F::zero()),
        Bytecode::Mod => (F::from_u128(Opcode::Mod.index() as u128), F::zero()),
        Bytecode::LdTrue => (F::from_u128(Opcode::LdTrue.index() as u128), F::zero()),
        Bytecode::LdFalse => (F::from_u128(Opcode::LdFalse.index() as u128), F::zero()),
        Bytecode::Eq => (F::from_u128(Opcode::Eq.index() as u128), F::zero()),
        Bytecode::Neq => (F::from_u128(Opcode::Neq.index() as u128), F::zero()),
        Bytecode::Le => (F::from_u128(Opcode::Le.index() as u128), F::zero()),
        Bytecode::Lt => (F::from_u128(Opcode::Lt.index() as u128), F::zero()),
        Bytecode::Ge => (F::from_u128(Opcode::Ge.index() as u128), F::zero()),
        Bytecode::Gt => (F::from_u128(Opcode::Gt.index() as u128), F::zero()),
        Bytecode::Shl => (F::from_u128(Opcode::Shl.index() as u128), F::zero()),
        Bytecode::Shr => (F::from_u128(Opcode::Shr.index() as u128), F::zero()),
        Bytecode::BitAnd => (F::from_u128(Opcode::BitAnd.index() as u128), F::zero()),
        Bytecode::BitOr => (F::from_u128(Opcode::BitOr.index() as u128), F::zero()),
        Bytecode::Xor => (F::from_u128(Opcode::Xor.index() as u128), F::zero()),
        Bytecode::And => (F::from_u128(Opcode::And.index() as u128), F::zero()),
        Bytecode::Or => (F::from_u128(Opcode::Or.index() as u128), F::zero()),
        Bytecode::Not => (F::from_u128(Opcode::Not.index() as u128), F::zero()),
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
        Bytecode::Abort => (F::from_u128(Opcode::Abort.index() as u128), F::zero()),
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
        Bytecode::ReadRef => (F::from_u128(Opcode::ReadRef.index() as u128), F::zero()),
        Bytecode::WriteRef => (F::from_u128(Opcode::WriteRef.index() as u128), F::zero()),
        Bytecode::FreezeRef => (F::from_u128(Opcode::FreezeRef.index() as u128), F::zero()),
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
        _ => unimplemented!("{:?}", bytecode),
    }
}

// convert BytecodeInfo into a vector of field values
impl<F: FieldExt> From<&BytecodeInfo> for Vec<F> {
    fn from(bytecode_info: &BytecodeInfo) -> Vec<F> {
        let mut field_values = vec![
            F::from_u128(bytecode_info.module_index as u128),
            F::from_u128(bytecode_info.function_index as u128),
            F::from_u128(bytecode_info.pc as u128),
        ];

        let (opcode, operand) = convert_bytecode_to_fields(bytecode_info.bytecode.clone());
        field_values.push(opcode);
        field_values.push(operand);

        field_values
    }
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct BytecodeTable(Vec<BytecodeInfo>);

impl BytecodeTable {
    pub fn new(bytecodes: Vec<BytecodeInfo>) -> Self {
        Self(bytecodes)
    }

    pub fn into_inner(self) -> Vec<BytecodeInfo> {
        self.0
    }
}

impl Deref for BytecodeTable {
    type Target = Vec<BytecodeInfo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for BytecodeTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// convert BytecodeTable into a vector of vector of field values
impl<F: FieldExt> From<&BytecodeTable> for Vec<Vec<F>> {
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
                                func_def.function.0,
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
        let mut script_bytecodes = BytecodeTable::from(script);
        let mut modules_bytecodes = BytecodeTable::from(modules);
        let mut bytecodes = Vec::new();
        bytecodes.append(&mut *script_bytecodes);
        bytecodes.append(&mut *modules_bytecodes);
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
