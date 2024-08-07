use crate::witness::static_info::bytecode::BytecodeInfo;
use crate::witness::static_info::constant::ConstantInfo;
use crate::witness::static_info::function::FunctionInfo;
use crate::witness::utils::ModuleIdMapping;
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;

pub mod bytecode;
pub mod constant;
pub mod function;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct StaticInfo {
    pub bytecode_info: Vec<BytecodeInfo>,
    pub function_info: Vec<FunctionInfo>,
    pub constant_info: Vec<ConstantInfo>,
}

impl StaticInfo {
    pub fn generate(module_id: &ModuleId, package: &CompiledPackage) -> Self {
        let modules = package.all_modules_map();
        let deps = modules
            .get_transitive_dependencies(module_id)
            .unwrap()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let module_id_mapping = ModuleIdMapping::construct(module_id, package);
        StaticInfo {
            bytecode_info: bytecode::parse_dependency(&module_id_mapping, &deps),
            function_info: function::parse_dependency(&module_id_mapping, &deps),
            constant_info: constant::parse_dependency(&module_id_mapping, &deps),
        }
    }
}
