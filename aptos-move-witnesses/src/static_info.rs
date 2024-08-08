use crate::static_info::bytecode::BytecodeInfo;
use crate::static_info::constant::ConstantInfo;
use crate::static_info::function::FunctionInfo;
use crate::utils::ModuleIdMapping;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_package::compilation::compiled_package::CompiledPackage;

pub mod bytecode;
pub mod constant;
pub mod function;

pub struct StaticInfo {
    pub bytecode_info: Vec<BytecodeInfo>,
    pub function_info: Vec<FunctionInfo>,
    pub constant_info: Vec<ConstantInfo>,
    pub module_id_mapping: ModuleIdMapping,
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
            bytecode_info: bytecode::parse_bytecode(&module_id_mapping, &deps),
            function_info: function::parse_function(&module_id_mapping, &deps),
            constant_info: constant::parse_constant(&module_id_mapping, &deps),
            module_id_mapping,
        }
    }

    pub fn get_constant(&self, module_index: usize, constant_index: usize) -> Option<MoveValue> {
        self.constant_info
            .iter()
            .find(|c| c.module_index == module_index && c.constant_index == constant_index)
            .map(|c| c.value.clone())
    }
}
