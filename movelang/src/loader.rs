// Copyright (c) zkMove Authors

use move_binary_format::errors::VMResult;
use move_binary_format::file_format::FunctionHandleIndex;
use move_vm_runtime::loader::{Function, Loader};
use move_vm_runtime::native_functions::NativeFunctions;
use move_vm_runtime::session::LoadedFunctionInstantiation;
use move_vm_types::data_store::DataStore;
use move_vm_types::loaded_data::runtime_types::Type;
use std::sync::Arc;

pub struct MoveLoader {
    loader: Loader,
}

impl MoveLoader {
    pub fn new() -> Self {
        let native_functions = NativeFunctions::new(vec![]).expect("should never failed.");
        MoveLoader {
            loader: Loader::new(native_functions),
        }
    }

    pub fn load_script(
        &self,
        script_blob: &[u8],
        data_store: &impl DataStore,
    ) -> VMResult<(Arc<Function>, Vec<Type>)> {
        let (
            main,
            LoadedFunctionInstantiation {
                type_arguments: _,
                parameters: arg_types,
                return_: _,
            },
        ) = self.loader.load_script(script_blob, &[], data_store)?;
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
