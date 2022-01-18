// Copyright (c) zkMove Authors

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
use std::cell::RefCell;

#[derive(Clone)]
pub struct StateStore {
    modules: RefCell<HashMap<ModuleId, Vec<u8>>>,
}

impl StateStore {
    pub fn new() -> Self {
        Self {
            modules: RefCell::new(HashMap::new()),
        }
    }

    pub fn add_module(&mut self, compiled_module: CompiledModule) {
        let module_id = compiled_module.self_id();
        let mut bytes = vec![];
        compiled_module.serialize(&mut bytes).unwrap();
        self.modules.borrow_mut().insert(module_id, bytes);
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct State<'s> {
    pub state_store: &'s StateStore,
}

impl<'s> State<'s> {
    pub fn new(state_store: &'s StateStore) -> Self {
        State { state_store }
    }

    pub fn state_store(&'s self) -> &'s StateStore {
        self.state_store
    }
}

impl<'s> DataStore for State<'s> {
    fn load_resource(
        &mut self,
        _addr: AccountAddress,
        _ty: &Type,
    ) -> PartialVMResult<&mut GlobalValue> {
        unimplemented!()
    }

    fn load_module(&self, module_id: &ModuleId) -> VMResult<Vec<u8>> {
        let modules_ref = self.state_store.modules.borrow();
        let module = modules_ref.get(module_id).ok_or_else(|| {
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
        self.state_store
            .modules
            .borrow_mut()
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
        Ok(self.state_store.modules.borrow().contains_key(module_id))
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
