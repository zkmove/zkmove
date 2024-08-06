use crate::witness::utils::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_package::compilation::compiled_package::CompiledPackage;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ConstantInfo {
    pub module_index: usize,
    pub constant_index: usize,
    pub value: MoveValue,
}

pub fn parse_package(module_id: &ModuleId, package: &CompiledPackage) -> Vec<ConstantInfo> {
    let modules = package.all_modules_map();
    let deps = modules.get_transitive_dependencies(module_id).unwrap();
    // todo: pass in module_id_mapping as parameter
    let module_id_mapping = ModuleIdMapping::construct(module_id, package);

    deps.iter()
        .flat_map(|module| {
            module
                .constant_pool()
                .iter()
                .enumerate()
                .map(|(idx, constant)| {
                    #[allow(clippy::expect_fun_call)]
                    let value = constant.deserialize_constant().expect(&format!(
                        "deserialize_constant {} at module {:?} should not fail",
                        idx,
                        module.self_id()
                    ));
                    ConstantInfo {
                        module_index: module_id_mapping.get_module_index(&module.self_id()),
                        constant_index: idx,
                        value,
                    }
                })
        })
        .collect()
}
