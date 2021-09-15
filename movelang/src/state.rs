use move_binary_format::errors::{Location, PartialVMError};
use move_binary_format::errors::{PartialVMResult, VMResult};
use move_binary_format::CompiledModule;
use move_core_types::{
    account_address::AccountAddress, language_storage::ModuleId, vm_status::StatusCode,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    values::{GlobalValue, Value},
};
use std::collections::HashMap;

pub use move_vm_types::data_store::DataStore;

pub struct StateStore {
    modules: HashMap<ModuleId, Vec<u8>>,
}

impl StateStore {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn add_module(&mut self, compiled_module: CompiledModule) {
        let module_id = compiled_module.self_id();
        let mut bytes = vec![];
        compiled_module.serialize(&mut bytes).unwrap();
        self.modules.insert(module_id, bytes);
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DataStore for StateStore {
    fn load_resource(
        &mut self,
        _addr: AccountAddress,
        _ty: &Type,
    ) -> PartialVMResult<&mut GlobalValue> {
        unimplemented!()
    }

    fn load_module(&self, module_id: &ModuleId) -> VMResult<Vec<u8>> {
        let module = self.modules.get(module_id).ok_or_else(|| {
            PartialVMError::new(StatusCode::MISSING_DEPENDENCY)
                .with_message(format!(
                    "failed to find module {:?} in data store",
                    module_id
                ))
                .finish(Location::Undefined)
        })?;
        Ok(module.clone())
    }

    fn publish_module(&mut self, module_id: &ModuleId, blob: Vec<u8>) -> VMResult<()> {
        self.modules
            .insert(module_id.clone(), blob)
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::MISSING_DEPENDENCY)
                    .with_message(format!(
                        "failed to put module {:?} into data store.",
                        module_id
                    ))
                    .finish(Location::Undefined)
            })?;
        Ok(())
    }

    fn exists_module(&self, module_id: &ModuleId) -> VMResult<bool> {
        Ok(self.modules.contains_key(module_id))
    }

    fn emit_event(
        &mut self,
        _guid: Vec<u8>,
        _seq_num: u64,
        _ty: Type,
        _val: Value,
    ) -> PartialVMResult<()> {
        unimplemented!()
    }
}
