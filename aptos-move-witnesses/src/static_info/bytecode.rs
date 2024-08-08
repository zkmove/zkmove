// Copyright (c) zkMove Authors

use crate::static_info::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_binary_format::binary_views::{BinaryIndexedView, FunctionView};
use move_binary_format::file_format::{
    Bytecode, CompiledModule, FunctionDefinitionIndex, SignatureToken,
};
use movelang::type_transition;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BytecodeInfo {
    pub module_index: usize,
    pub function_index: usize,
    pub pc: u16,
    pub bytecode: Bytecode,
    /// types that outputted by the bytecode
    pub ty_out: Vec<SignatureToken>,
}

impl BytecodeInfo {
    pub fn new(
        module_index: usize,
        function_index: usize,
        pc: u16,
        bytecode: Bytecode,
        ty_out: Vec<SignatureToken>,
    ) -> Self {
        BytecodeInfo {
            module_index,
            function_index,
            pc,
            bytecode,
            ty_out,
        }
    }
}

pub(crate) fn parse_bytecode(
    module_id_mapping: &ModuleIdMapping,
    deps: &[CompiledModule],
) -> Vec<BytecodeInfo> {
    deps.iter()
        .flat_map(|module| {
            let module_index = module_id_mapping.get_module_index(&module.self_id());
            parse_module(module, module_index)
        })
        .collect()
}

fn parse_module(module: &CompiledModule, module_index: usize) -> Vec<BytecodeInfo> {
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
                    .map(move |(i, transition)| BytecodeInfo {
                        module_index,
                        function_index: func_index,
                        pc: i,
                        bytecode: transition.instr,
                        ty_out: transition.output,
                    })
                    .collect::<Vec<_>>();
                Some(rows)
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::static_info::bytecode::{parse_module, BytecodeInfo};
    use move_binary_format::file_format::{
        empty_module, Bytecode, CodeUnit, CompiledModule, FunctionDefinition, FunctionHandle,
        FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex, SignatureIndex, SignatureToken,
        Visibility,
    };
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
        let bytecodes = parse_module(&module, 0);

        let expected_bytecode_table = vec![
            BytecodeInfo::new(0, 0, 0, Bytecode::LdU64(1u64), vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 0, 1, Bytecode::LdU64(2u64), vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 0, 2, Bytecode::Add, vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 0, 3, Bytecode::Pop, vec![]),
            BytecodeInfo::new(0, 0, 4, Bytecode::Ret, vec![]),
            BytecodeInfo::new(0, 1, 0, Bytecode::LdU64(1u64), vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 1, 1, Bytecode::LdU64(2u64), vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 1, 2, Bytecode::Sub, vec![SignatureToken::U64]),
            BytecodeInfo::new(0, 1, 3, Bytecode::Pop, vec![]),
            BytecodeInfo::new(0, 1, 4, Bytecode::Ret, vec![]),
        ];

        assert_eq!(bytecodes, expected_bytecode_table, "result is not expected");
    }
}
