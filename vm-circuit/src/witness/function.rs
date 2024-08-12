// Copyright (c) zkMove Authors

use crate::witness::utils::ModuleIdMapping;
use move_binary_format::file_format::{CompiledModule, FunctionHandleIndex};
use move_binary_format::views::FunctionHandleView;
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;
use types::Field;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FunctionTableRow {
    module_index: usize,
    function_handle_index: usize,
    def_module_index: usize,
    function_index: usize,
    num_arg: usize,
}

impl FunctionTableRow {
    pub fn new(
        module_index: usize,
        function_handle_index: usize,
        def_module_index: usize,
        function_index: usize,
        num_arg: usize,
    ) -> Self {
        FunctionTableRow {
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

pub fn parse_package(module_id: &ModuleId, package: &CompiledPackage) -> Vec<FunctionTableRow> {
    let modules = package.all_modules_map();
    let deps = modules.get_transitive_dependencies(module_id).unwrap();
    // todo: pass in module_id_mapping as parameter
    let module_id_mapping = ModuleIdMapping::construct(module_id, package);
    deps.iter()
        .flat_map(|module| {
            let module_index = module_id_mapping.get_module_index(&module.self_id());
            parse_module(module, module_index, &module_id_mapping)
        })
        .collect()
}

fn parse_module(
    module: &CompiledModule,
    module_index: usize,
    module_id_mapping: &ModuleIdMapping,
) -> Vec<FunctionTableRow> {
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
                .expect(&format!("cannot find function def for {:?}", fh));
            let num_arg = fh_view.arg_count();
            FunctionTableRow {
                module_index,
                function_handle_index: fh_index,
                def_module_index,
                function_index,
                num_arg,
            }
        })
        .collect()
}
