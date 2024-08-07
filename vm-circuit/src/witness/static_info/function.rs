// Copyright (c) zkMove Authors

use crate::witness::utils::ModuleIdMapping;
use move_binary_format::file_format::{CompiledModule, FunctionHandleIndex};
use move_binary_format::views::FunctionHandleView;
use types::Field;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FunctionInfo {
    module_index: usize,
    function_handle_index: usize,
    def_module_index: usize,
    function_index: usize,
    num_arg: usize,
}

impl FunctionInfo {
    pub fn new(
        module_index: usize,
        function_handle_index: usize,
        def_module_index: usize,
        function_index: usize,
        num_arg: usize,
    ) -> Self {
        FunctionInfo {
            module_index,
            function_handle_index,
            def_module_index,
            function_index,
            num_arg,
        }
    }

    pub fn to_fe<F: Field>(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_handle_index as u128),
            F::from_u128(self.def_module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.num_arg as u128),
        ]
    }
}

pub(crate) fn parse_dependency(
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
    module_index: usize,
    module_id_mapping: &ModuleIdMapping,
) -> Vec<FunctionInfo> {
    module
        .function_handles
        .iter()
        .enumerate()
        .map(|(fh_index, fh)| {
            let fh_view = FunctionHandleView::new(module, fh);
            let (def_module_index, def_module) = module_id_mapping.get_module(&fh_view.module_id());
            let function_index = def_module
                .function_defs
                .iter()
                .enumerate()
                .find_map(move |(index, func)| {
                    if func.function == FunctionHandleIndex(fh_index as u16) {
                        Some(index)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| panic!("cannot find function def for {:?}", fh));
            let num_arg = fh_view.arg_count();
            FunctionInfo {
                module_index,
                function_handle_index: fh_index,
                def_module_index,
                function_index,
                num_arg,
            }
        })
        .collect()
}
