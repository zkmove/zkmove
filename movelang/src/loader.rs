use move_binary_format::errors::{PartialVMResult, VMResult};
use move_core_types::{account_address::AccountAddress, language_storage::ModuleId};
use move_vm_runtime::loader::{Function, Loader};
use move_vm_runtime::logging::NoContextLog;
use move_vm_types::{
    data_store::DataStore,
    loaded_data::runtime_types::Type,
    values::{GlobalValue, Value},
};

use std::sync::Arc;

pub struct DummyDataStore {}

impl DummyDataStore {
    pub fn new() -> Self {
        DummyDataStore {}
    }
}

impl Default for DummyDataStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DataStore for DummyDataStore {
    fn load_resource(
        &mut self,
        _addr: AccountAddress,
        _ty: &Type,
    ) -> PartialVMResult<&mut GlobalValue> {
        unimplemented!()
    }

    fn load_module(&self, _module_id: &ModuleId) -> VMResult<Vec<u8>> {
        unimplemented!()
    }

    fn publish_module(&mut self, _module_id: &ModuleId, _blob: Vec<u8>) -> VMResult<()> {
        unimplemented!()
    }

    fn exists_module(&self, _module_id: &ModuleId) -> VMResult<bool> {
        unimplemented!()
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

pub struct MoveLoader {
    loader: Loader,
}

impl MoveLoader {
    pub fn new() -> Self {
        MoveLoader {
            loader: Loader::new(),
        }
    }

    pub fn load_script(&self, script_blob: &[u8]) -> VMResult<(Arc<Function>, Vec<Type>)> {
        let log_context = NoContextLog::new();
        let mut data_store = DummyDataStore::new();
        let (main, _ty_args, arg_types) =
            self.loader
                .load_script(script_blob, &[], &mut data_store, &log_context)?;
        Ok((main, arg_types))
    }
}

impl Default for MoveLoader {
    fn default() -> Self {
        Self::new()
    }
}
