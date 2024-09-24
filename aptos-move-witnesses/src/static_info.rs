use crate::static_info::bytecode::BytecodeInfo;
use crate::static_info::constant::ConstantInfo;
use crate::static_info::function::FunctionInfo;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_package::compilation::compiled_package::CompiledPackage;
use std::collections::{BTreeMap, HashMap};
use std::iter;

pub mod bytecode;
pub mod constant;
pub mod function;

#[derive(Clone, Default, Debug)]
pub struct ModuleIdMapping(HashMap<ModuleId, (u32 /*module_index*/, CompiledModule)>);

impl ModuleIdMapping {
    pub fn construct(module_id: &ModuleId, package: &CompiledPackage) -> Self {
        let modules = package.all_modules_map();
        let mut deps = modules.get_transitive_dependencies(module_id).unwrap();
        deps.sort_by_key(|m| m.self_id());
        let mut mapping = HashMap::new();
        let module = modules
            .get_module(module_id)
            .unwrap_or_else(|_| panic!("cannot find module {:?}", module_id));
        for (idx, m) in iter::once(module).chain(deps).enumerate() {
            mapping.insert(m.self_id(), (idx as u32, m.clone()));
        }
        ModuleIdMapping(mapping)
    }
    pub fn get_module_index(&self, module_id: &ModuleId) -> u32 {
        let (module_index, _) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        *module_index
    }
    pub fn get_module(&self, module_id: &ModuleId) -> (u32, &CompiledModule) {
        let (module_index, module) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        (*module_index, module)
    }
}

#[derive(Clone, Default, Debug)]
pub struct StaticInfo {
    pub bytecode_info: BTreeMap<u32, BTreeMap<u16, Vec<BytecodeInfo>>>,
    pub function_info: Vec<FunctionInfo>,
    pub constant_info: Vec<ConstantInfo>,
    pub module_id_mapping: ModuleIdMapping,
    pub entry: Entry,
}

impl StaticInfo {
    pub fn generate(module_id: &ModuleId, entry_func: u16, package: &CompiledPackage) -> Self {
        let modules = package.all_modules_map();
        let mut deps = modules
            .get_transitive_dependencies(module_id)
            .unwrap()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        deps.push(modules.get_module(module_id).unwrap().clone());
        let module_id_mapping = ModuleIdMapping::construct(module_id, package);

        let module_index = module_id_mapping.get_module_index(module_id);
        StaticInfo {
            bytecode_info: bytecode::parse_bytecode(&module_id_mapping, &deps),
            function_info: function::parse_function(&module_id_mapping, &deps),
            constant_info: constant::parse_constant(&module_id_mapping, &deps),
            module_id_mapping,
            entry: Entry {
                module_index,
                function_index: entry_func,
            },
        }
    }

    pub fn get_bytecode(
        &self,
        module_index: u32,
        function_index: u16,
        pc: usize,
    ) -> Option<BytecodeInfo> {
        self.bytecode_info
            .get(&module_index)
            .and_then(|t| t.get(&function_index))
            .and_then(|v| v.get(pc))
            .cloned()
    }

    pub fn get_constant(&self, module_index: u32, constant_index: u16) -> Option<MoveValue> {
        self.constant_info
            .iter()
            .find(|c| c.module_index == module_index && c.constant_index == constant_index)
            .map(|c| c.value.clone())
    }

    /// get function `fh_idx` in the function handle table of `module_index`
    pub fn get_function(&self, module_index: u32, fh_idx: u16) -> Option<FunctionInfo> {
        self.function_info
            .iter()
            .find(|f| f.module_index == module_index && f.function_handle_index == fh_idx)
            .cloned()
    }

    /// find entry function by `module_index` and `function_index` of entry function.
    /// `module_index` and `def_module_index` should be same.
    pub fn get_entry_function(
        &self,
        module_index: u32,
        function_index: u16,
    ) -> Option<FunctionInfo> {
        self.function_info
            .iter()
            .find(|f| {
                f.module_index == module_index
                    && f.def_module_index == module_index
                    && f.function_index == function_index
            })
            .cloned()
    }
}

#[derive(Clone, Default, Debug)]
pub struct Entry {
    pub module_index: u32,
    pub function_index: u16,
}
