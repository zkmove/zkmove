use crate::interpreter::Interpreter;
use error::{RuntimeError, StatusCode, VmResult};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_vm_runtime::loader::Resolver;
use move_vm_runtime::native_extensions::NativeContextExtensions;
use move_vm_types::data_store::DataStore;
use move_vm_types::loaded_data::runtime_types::Type;
use movelang::value::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub type UnboxedNativeFunction = dyn Fn(&mut NativeContext, Vec<Type>, VecDeque<Value>) -> VmResult<Value>
    + Send
    + Sync
    + 'static;

pub type NativeFunction = Arc<UnboxedNativeFunction>;

pub type NativeFunctionTable = Vec<(AccountAddress, Identifier, Identifier, NativeFunction)>;

pub struct NativeFunctions(
    HashMap<AccountAddress, HashMap<String, HashMap<String, NativeFunction>>>,
);

impl NativeFunctions {
    pub fn resolve(
        &self,
        addr: &AccountAddress,
        module_name: &str,
        func_name: &str,
    ) -> Option<NativeFunction> {
        self.0.get(addr)?.get(module_name)?.get(func_name).cloned()
    }

    pub fn new<I>(natives: I) -> VmResult<Self>
    where
        I: IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)>,
    {
        let mut map = HashMap::new();
        for (addr, module_name, func_name, func) in natives.into_iter() {
            let modules = map.entry(addr).or_insert_with(HashMap::new);
            let funcs = modules
                .entry(module_name.into_string())
                .or_insert_with(HashMap::new);

            if funcs.insert(func_name.into_string(), func).is_some() {
                return Err(RuntimeError::new(
                    StatusCode::UnknownInvariantViolationError,
                ));
            }
        }
        Ok(Self(map))
    }
}

#[allow(dead_code)]
pub struct NativeContext<'a, 'b> {
    interpreter: &'a mut Interpreter,
    data_store: &'a mut dyn DataStore,
    resolver: &'a Resolver<'a>,
    extensions: &'a mut NativeContextExtensions<'b>,
}

impl<'a, 'b> NativeContext<'a, 'b> {
    pub(crate) fn new(
        interpreter: &'a mut Interpreter,
        data_store: &'a mut dyn DataStore,
        resolver: &'a Resolver<'a>,
        extensions: &'a mut NativeContextExtensions<'b>,
    ) -> Self {
        Self {
            interpreter,
            data_store,
            resolver,
            extensions,
        }
    }

    pub fn extensions(&self) -> &NativeContextExtensions<'b> {
        self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut NativeContextExtensions<'b> {
        self.extensions
    }
}
