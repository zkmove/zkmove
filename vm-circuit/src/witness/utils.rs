use move_core_types::language_storage::ModuleId;
use move_core_types::u256::U256;
use move_package::compilation::compiled_package::CompiledPackage;
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

pub struct ModuleIdMapping(Vec<ModuleId>);

impl ModuleIdMapping {
    pub fn construct(module_id: &ModuleId, package: &CompiledPackage) -> Self {
        let modules = package.all_modules_map();
        let deps = modules.get_transitive_dependencies(module_id).unwrap();
        let mut module_ids = deps
            .iter()
            .map(|module| module.self_id())
            .collect::<Vec<_>>();
        module_ids.sort();
        Self(module_ids)
    }
    pub fn get_module_index(&self, module_id: ModuleId) -> usize {
        self.0
            .iter()
            .position(|m| m == &module_id)
            .expect(&format!("cannot find module {:?}", module_id))
    }
}
