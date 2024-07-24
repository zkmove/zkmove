use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_core_types::u256::U256;
use move_package::compilation::compiled_package::CompiledPackage;
use std::collections::HashMap;
use types::Field;

pub fn convert_u256_to_fe_pair<F: Field>(input: U256) -> (F, F) {
    let bytes = input.to_le_bytes();
    let mut repr = F::Repr::default();
    repr[..16].copy_from_slice(&bytes[..16]);
    let lo = F::from_repr(repr).unwrap();
    repr[..16].copy_from_slice(&bytes[16..]);
    let hi = F::from_repr(repr).unwrap();
    (lo, hi)
}

pub struct ModuleIdMapping(HashMap<ModuleId, (usize /*module_index*/, CompiledModule)>);

impl ModuleIdMapping {
    pub fn construct(module_id: &ModuleId, package: &CompiledPackage) -> Self {
        let modules = package.all_modules_map();
        let deps = modules.get_transitive_dependencies(module_id).unwrap();
        let mut mapping = HashMap::new();
        for (idx, dep) in deps.into_iter().enumerate() {
            mapping.insert(dep.self_id(), (idx, dep.clone()));
        }
        ModuleIdMapping(mapping)
    }
    pub fn get_module_index(&self, module_id: &ModuleId) -> usize {
        let (module_index, _) = self
            .0
            .get(module_id)
            .expect(&format!("cannot find module {:?}", module_id));
        *module_index
    }
    pub fn get_module(&self, module_id: &ModuleId) -> (usize, &CompiledModule) {
        let (module_index, module) = self
            .0
            .get(module_id)
            .expect(&format!("cannot find module {:?}", module_id));
        (*module_index, module)
    }
}
