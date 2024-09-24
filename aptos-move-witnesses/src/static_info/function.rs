// Copyright (c) zkMove Authors

use crate::static_info::ModuleIdMapping;
use move_binary_format::file_format::CompiledModule;
use move_binary_format::views::{FunctionDefinitionView, FunctionHandleView};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FunctionInfo {
    pub module_index: u32,
    pub function_handle_index: u16,
    pub def_module_index: u32,
    pub function_index: u16,
    pub num_arg: u8,
}

impl FunctionInfo {
    pub fn new(
        module_index: u32,
        function_handle_index: u16,
        def_module_index: u32,
        function_index: u16,
        num_arg: u8,
    ) -> Self {
        FunctionInfo {
            module_index,
            function_handle_index,
            def_module_index,
            function_index,
            num_arg,
        }
    }

    pub fn num_arg(&self) -> u8 {
        self.num_arg
    }
}

pub(crate) fn parse_function(
    module_id_mapping: &ModuleIdMapping,
    deps: &[CompiledModule],
) -> Vec<FunctionInfo> {
    deps.iter()
        .flat_map(|module| {
            let module_index = module_id_mapping.get_module_index(&module.self_id());
            parse_module(module, module_index, module_id_mapping)
        })
        .collect()
}

fn parse_module(
    module: &CompiledModule,
    module_index: u32,
    module_id_mapping: &ModuleIdMapping,
) -> Vec<FunctionInfo> {
    module
        .function_handles
        .iter()
        .enumerate()
        .map(|(fh_index, fh)| {
            let fh_view = FunctionHandleView::new(module, fh);
            let func_name = fh_view.name();
            let (def_module_index, def_module) = module_id_mapping.get_module(&fh_view.module_id());

            let function_index = def_module
                .function_defs
                .iter()
                .enumerate()
                .find_map(move |(index, func)| {
                    if FunctionDefinitionView::new(def_module, func)
                        .name()
                        .as_str()
                        == func_name.as_str()
                    {
                        Some(index)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("cannot find function def for {:?}", fh));
            let num_arg = fh_view.arg_count();
            FunctionInfo {
                module_index,
                function_handle_index: fh_index as u16,
                def_module_index,
                function_index: function_index as u16,
                num_arg: num_arg as u8,
            }
        })
        .collect()
}
