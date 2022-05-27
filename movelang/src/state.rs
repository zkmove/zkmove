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

use move_core_types::value::MoveTypeLayout;
pub use move_vm_types::data_store::DataStore;
use std::cell::RefCell;

#[derive(Clone)]
pub struct StateStore {
    modules: RefCell<HashMap<ModuleId, Vec<u8>>>,
    module_table: RefCell<Vec<ModuleId>>,
}

impl StateStore {
    pub fn new() -> Self {
        Self {
            modules: RefCell::new(HashMap::new()),
            module_table: RefCell::new(Vec::new()),
        }
    }

    pub fn add_module(&mut self, compiled_module: CompiledModule) {
        let module_id = compiled_module.self_id();
        let mut bytes = vec![];
        compiled_module.serialize(&mut bytes).unwrap();
        self.modules.borrow_mut().insert(module_id.clone(), bytes);
        self.module_table.borrow_mut().push(module_id);
    }

    // module index is used in vm circuit to lookup the bytecode in the module
    // todo: we need a more elegant approach to maintain the module table
    pub fn module_index(&self, module_id: &ModuleId) -> Option<u16> {
        let mut module_index = None;
        for (index, id) in self.module_table.borrow().iter().enumerate() {
            if id == module_id {
                module_index = Some(index as u16 + 1); // add 1, to reserve 0 for txn script
            }
        }
        module_index
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
        let modules_ref = self.modules.borrow();
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
        self.modules
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
        self.module_table.borrow_mut().push(module_id.clone());
        Ok(())
    }

    fn exists_module(&self, module_id: &ModuleId) -> VMResult<bool> {
        Ok(self.modules.borrow().contains_key(module_id))
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

    fn events(&self) -> &Vec<(Vec<u8>, u64, Type, MoveTypeLayout, Value)> {
        unimplemented!()
    }
}
