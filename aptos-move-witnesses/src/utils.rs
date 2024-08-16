use crate::step_state::SubIndex;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;
use move_vm_runtime::witnessing::traced_value::SimpleValue;
use std::collections::HashMap;
use std::iter;
use types::Field;

pub trait SubIndexUtils {
    fn into_u128(&self) -> u128;
    fn from_u128(sub_index: u128) -> Self;
    fn depth(&self) -> usize;
    fn parents(&self) -> Option<Vec<Self>>
    where
        Self: Sized;
}

impl SubIndexUtils for SubIndex {
    fn into_u128(&self) -> u128 {
        unimplemented!()
    }
    fn from_u128(sub_index: u128) -> Self {
        unimplemented!()
    }
    fn depth(&self) -> usize {
        let vec: Vec<_> = self.iter().rev().skip_while(|&x| *x == 0).collect();
        vec.len()
    }
    fn parents(&self) -> Option<Vec<Self>> {
        //TODO: a depth-n sub_index must have n parents. Return all parents in a vector,
        // in a order starting with direct relatives.
        // for example, [1,2,3]'s parents will be [[1,2],[1],[0]]

        unimplemented!()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader {
    pub flen: u16,
    pub len: u16,
}

impl ValueHeader {
    pub fn new(flen: u16, len: u16) -> Self {
        Self { flen, len }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flen
    // bit[16..32], len
    pub fn value(&self) -> u64 {
        (self.flen as u64) + ((self.len as u64) << 16)
    }

    pub fn to_fe<F: Field>(&self) -> (F, F) {
        (
            F::from_u128(self.flen as u128),
            F::from_u128(self.len as u128),
        )
    }
}

impl From<ValueHeader> for SimpleValue {
    fn from(value: ValueHeader) -> SimpleValue {
        SimpleValue::U64(value.value())
    }
}
impl From<SimpleValue> for ValueHeader {
    fn from(value: SimpleValue) -> ValueHeader {
        match value {
            SimpleValue::U64(v) => {
                let flen = (v & 0xFFFF) as u16;
                let len = ((v & 0xFFFF0000) >> 16) as u16;
                ValueHeader { flen, len }
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Default)]
pub struct ModuleIdMapping(HashMap<ModuleId, (usize /*module_index*/, CompiledModule)>);

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
            mapping.insert(m.self_id(), (idx, m.clone()));
        }
        ModuleIdMapping(mapping)
    }
    pub fn get_module_index(&self, module_id: &ModuleId) -> usize {
        let (module_index, _) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        *module_index
    }
    pub fn get_module(&self, module_id: &ModuleId) -> (usize, &CompiledModule) {
        let (module_index, module) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        (*module_index, module)
    }
}
