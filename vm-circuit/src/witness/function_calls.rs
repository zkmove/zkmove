// Copyright (c) zkMove Authors

use crate::witness::call_trace_table::NameToIdxMapping;

use itertools::Itertools;
use move_binary_format::access::{ModuleAccess, ScriptAccess};
use move_binary_format::file_format::{Bytecode, CompiledScript};
use move_binary_format::views::ModuleView;
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::ident_str;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::ModuleId;
use move_core_types::resolver::ModuleResolver;
use movelang::generic_call_graph::RemoteStore;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum EntryType {
    CALL = 0,
    RET,
}

// a struct to record the location of function call and return
#[derive(Clone, Debug, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionCall {
    pub type_: EntryType,
    pub module_index: u16,
    pub function_index: u16,
    pub pc: u16,
    pub next_module_index: u16,
    pub next_function_index: u16,
    pub next_pc: u16,
}

pub struct FunctionCalls(pub Vec<FunctionCall>);

impl<'a> From<(&'a CompiledScript, &'a [CompiledModule])> for FunctionCalls {
    fn from((script, deps): (&'a CompiledScript, &'a [CompiledModule])) -> Self {
        Self(generate(script, deps))
    }
}
impl<'a> From<(&'a ModuleId, &'a IdentStr, &'a [CompiledModule])> for FunctionCalls {
    fn from(
        (entry_module, entry_function_name, deps): (
            &'a ModuleId,
            &'a IdentStr,
            &'a [CompiledModule],
        ),
    ) -> Self {
        Self(generate_for_entry_function(
            entry_module,
            entry_function_name,
            deps,
        ))
    }
}

fn generate(script: &CompiledScript, deps: &[CompiledModule]) -> Vec<FunctionCall> {
    let store = {
        let mut s = RemoteStore::default();
        deps.iter().for_each(|dep| s.add_module(dep));
        s
    };
    let name_mapping = NameToIdxMapping::build(deps);
    let calls = Generator { store: &store }.generate_for_script(script);
    calls
        .into_iter()
        .map(|c| {
            let (m_idx, f_idx) =
                name_mapping.map_fn_name(c.module_id.as_ref(), &c.function_name.to_string().into());
            let (next_m_idx, next_f_idx) = name_mapping.map_fn_name(
                c.next_module_id.as_ref(),
                &c.next_function_name.to_string().into(),
            );

            FunctionCall {
                type_: c.type_,
                module_index: m_idx as u16,
                function_index: f_idx.0,
                pc: c.pc as u16,
                next_module_index: next_m_idx as u16,
                next_function_index: next_f_idx.0,
                next_pc: c.next_pc as u16,
            }
        })
        .sorted() // to keep the table data predictable
        .collect()
}

fn generate_for_entry_function(
    entry_module: &ModuleId,
    entry_function: &IdentStr,
    deps: &[CompiledModule],
) -> Vec<FunctionCall> {
    let store = {
        let mut s = RemoteStore::default();
        deps.iter().for_each(|dep| s.add_module(dep));
        s
    };
    let name_mapping = NameToIdxMapping::build(deps);
    let calls =
        Generator { store: &store }.generate_for_entry_function(entry_module, entry_function);
    calls
        .into_iter()
        .map(|c| {
            let (m_idx, f_idx) =
                name_mapping.map_fn_name(c.module_id.as_ref(), &c.function_name.to_string().into());
            let (next_m_idx, next_f_idx) = name_mapping.map_fn_name(
                c.next_module_id.as_ref(),
                &c.next_function_name.to_string().into(),
            );

            FunctionCall {
                type_: c.type_,
                module_index: m_idx as u16,
                function_index: f_idx.0,
                pc: c.pc as u16,
                next_module_index: next_m_idx as u16,
                next_function_index: next_f_idx.0,
                next_pc: c.next_pc as u16,
            }
        })
        .sorted() // to keep the table data predictable
        .collect()
}
struct Generator<'a, S> {
    store: &'a S,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct FunctionCallInfo {
    pub type_: EntryType,
    pub module_id: Option<ModuleId>,
    pub function_name: Identifier,
    pub pc: usize,
    pub next_module_id: Option<ModuleId>,
    pub next_function_name: Identifier,
    pub next_pc: usize,
}
impl<'a, S: ModuleResolver> Generator<'a, S> {
    fn generate_for_script(&self, access: &impl ScriptAccess) -> Vec<FunctionCallInfo> {
        let mut result = BTreeSet::default();
        let caller_module = None;
        let caller_function = ident_str!("main");
        for (pc, bytecode) in access.code().code.iter().enumerate() {
            match bytecode {
                Bytecode::Call(index) => {
                    let fh = access.function_handle_at(*index);
                    let module_handle = access.module_handle_at(fh.module);
                    let module_name = access.identifier_at(module_handle.name);
                    let module_address = access.address_identifier_at(module_handle.address);
                    let func_name = access.identifier_at(fh.name);
                    self.generate_for_call(
                        &mut result,
                        caller_module.clone(),
                        caller_function,
                        pc,
                        module_address,
                        module_name,
                        func_name,
                    );
                }
                Bytecode::CallGeneric(idx) => {
                    let fh =
                        access.function_handle_at(access.function_instantiation_at(*idx).handle);
                    let module_handle = access.module_handle_at(fh.module);
                    let module_name = access.identifier_at(module_handle.name);
                    let module_address = access.address_identifier_at(module_handle.address);
                    let func_name = access.identifier_at(fh.name);
                    self.generate_for_call(
                        &mut result,
                        caller_module.clone(),
                        caller_function,
                        pc,
                        module_address,
                        module_name,
                        func_name,
                    );
                }
                Bytecode::Ret => {
                    // ignored this ret
                }
                _ => {}
            }
        }
        result.into_iter().collect()
    }

    fn generate_for_entry_function(
        &self,
        entry_module: &ModuleId,
        entry_function: &IdentStr,
    ) -> Vec<FunctionCallInfo> {
        let caller_module =
            CompiledModule::deserialize(&self.store.get_module(entry_module).unwrap().unwrap())
                .unwrap();
        let caller_module_view = ModuleView::new(&caller_module);
        let entry_func = caller_module_view
            .function_definition(entry_function)
            .unwrap();

        let mut result = BTreeSet::default();
        let access = &caller_module;
        for (pc, bytecode) in entry_func.code().unwrap().code.iter().enumerate() {
            match bytecode {
                Bytecode::Call(index) => {
                    let fh = access.function_handle_at(*index);
                    let module_handle = access.module_handle_at(fh.module);
                    let module_name = access.identifier_at(module_handle.name);
                    let module_address = access.address_identifier_at(module_handle.address);
                    let func_name = access.identifier_at(fh.name);
                    self.generate_for_call(
                        &mut result,
                        Some(entry_module.clone()),
                        entry_function,
                        pc,
                        module_address,
                        module_name,
                        func_name,
                    );
                }
                Bytecode::CallGeneric(idx) => {
                    let fh =
                        access.function_handle_at(access.function_instantiation_at(*idx).handle);
                    let module_handle = access.module_handle_at(fh.module);
                    let module_name = access.identifier_at(module_handle.name);
                    let module_address = access.address_identifier_at(module_handle.address);
                    let func_name = access.identifier_at(fh.name);
                    self.generate_for_call(
                        &mut result,
                        Some(entry_module.clone()),
                        entry_function,
                        pc,
                        module_address,
                        module_name,
                        func_name,
                    );
                }
                Bytecode::Ret => {
                    // ignored this ret
                }
                _ => {}
            }
        }
        result.into_iter().collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_for_call(
        &self,
        result_set: &mut BTreeSet<FunctionCallInfo>,
        caller_module: Option<ModuleId>,
        caller_function: &IdentStr,
        caller_pc: usize,
        callee_module_address: &AccountAddress,
        callee_module_name: &IdentStr,
        callee_func_name: &IdentStr,
    ) {
        let callee_module_id = ModuleId::new(*callee_module_address, callee_module_name.into());
        if result_set.insert(FunctionCallInfo {
            type_: EntryType::CALL,
            module_id: caller_module.clone(),
            function_name: caller_function.into(),
            pc: caller_pc,
            next_module_id: Some(callee_module_id.clone()),
            next_function_name: callee_func_name.into(),
            next_pc: 0,
        }) {
            let m = self.store.get_module(&callee_module_id).unwrap().unwrap();
            let callee_module = CompiledModule::deserialize(&m).unwrap();
            let callee_code = {
                let module_view = ModuleView::new(&callee_module);
                let func = module_view.function_definition(callee_func_name).unwrap();
                func.code().cloned()
            };
            if let Some(callee_code) = callee_code {
                for (pc, bytecode) in callee_code.code.iter().enumerate() {
                    match bytecode {
                        Bytecode::Ret => {
                            result_set.insert(FunctionCallInfo {
                                type_: EntryType::RET,
                                module_id: Some(callee_module_id.clone()),
                                function_name: callee_func_name.into(),
                                pc,
                                next_module_id: caller_module.clone(),
                                next_function_name: caller_function.into(),
                                next_pc: caller_pc + 1,
                            });
                        }
                        Bytecode::Call(index) => {
                            let fh = callee_module.function_handle_at(*index);
                            let module_handle = callee_module.module_handle_at(fh.module);
                            let module_name = callee_module.identifier_at(module_handle.name);
                            let module_address =
                                callee_module.address_identifier_at(module_handle.address);
                            let func_name = callee_module.identifier_at(fh.name);
                            self.generate_for_call(
                                result_set,
                                Some(callee_module_id.clone()),
                                callee_func_name,
                                pc,
                                module_address,
                                module_name,
                                func_name,
                            );
                        }
                        Bytecode::CallGeneric(idx) => {
                            let fh = callee_module.function_handle_at(
                                callee_module.function_instantiation_at(*idx).handle,
                            );
                            let module_handle = callee_module.module_handle_at(fh.module);
                            let module_name = callee_module.identifier_at(module_handle.name);
                            let module_address =
                                callee_module.address_identifier_at(module_handle.address);
                            let func_name = callee_module.identifier_at(fh.name);
                            self.generate_for_call(
                                result_set,
                                Some(callee_module_id.clone()),
                                callee_func_name,
                                pc,
                                module_address,
                                module_name,
                                func_name,
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
