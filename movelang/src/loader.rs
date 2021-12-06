// Copyright (c) zkMove Authors

use move_binary_format::errors::VMResult;
use move_binary_format::file_format::FunctionHandleIndex;
use move_vm_runtime::loader::{Function, Loader};
use move_vm_runtime::logging::NoContextLog;
use move_vm_types::data_store::DataStore;
use move_vm_types::loaded_data::runtime_types::Type;
use std::sync::Arc;

pub struct MoveLoader {
    loader: Loader,
}

impl MoveLoader {
    pub fn new() -> Self {
        MoveLoader {
            loader: Loader::new(),
        }
    }

    pub fn load_script(
        &self,
        script_blob: &[u8],
        data_store: &mut impl DataStore,
    ) -> VMResult<(Arc<Function>, Vec<Type>)> {
        let log_context = NoContextLog::new();
        let (main, _ty_args, arg_types) =
            self.loader
                .load_script(script_blob, &[], data_store, &log_context)?;
        Ok((main, arg_types))
    }

    pub fn function_from_handle(
        &self,
        caller: &Arc<Function>,
        callee_idx: FunctionHandleIndex,
    ) -> Arc<Function> {
        let resolver = caller.get_resolver(&self.loader);
        resolver.function_from_handle(callee_idx)
    }
}

impl Default for MoveLoader {
    fn default() -> Self {
        Self::new()
    }
}
