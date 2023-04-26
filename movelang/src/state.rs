// Copyright (c) The Move Contributors
// Copyright (c) zkMove Authors

use move_binary_format::errors::{Location, PartialVMError, VMError};
use move_binary_format::errors::{PartialVMResult, VMResult};
use move_binary_format::CompiledModule;
use move_core_types::{
    account_address::AccountAddress as MoveAccountAddress, language_storage::ModuleId,
    vm_status::StatusCode as MoveStatusCode,
};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    values::{GlobalValue as MoveGlobalValue, Value},
};
use std::collections::HashMap;

use crate::account_address::AccountAddress;
use crate::loader::MoveLoader;
use crate::value::GlobalValue;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_core_types::gas_algebra::NumBytes;
use move_core_types::language_storage::TypeTag;
use move_core_types::resolver::ModuleResolver;
use move_core_types::value::MoveTypeLayout;
pub use move_vm_types::data_store::DataStore;
use std::cell::RefCell;
use std::collections::btree_map::BTreeMap;

#[derive(Clone)]
pub struct AccountData<F: FieldExt> {
    data_map: BTreeMap<Type, (MoveTypeLayout, GlobalValue<F>)>,
}

impl<F: FieldExt> AccountData<F> {
    fn new() -> Self {
        Self {
            data_map: BTreeMap::new(),
        }
    }
    fn global_value(&mut self, ty: &Type) -> &mut GlobalValue<F> {
        self.data_map
            .get_mut(ty)
            .map(|(_ty_layout, global_value)| global_value)
            .expect("global value must exist")
    }
}

#[derive(Clone)]
pub struct StateStore<F: FieldExt> {
    modules: RefCell<HashMap<ModuleId, Vec<u8>>>,
    module_table: RefCell<Vec<ModuleId>>,
    account_map: RefCell<BTreeMap<AccountAddress<F>, AccountData<F>>>,
}

impl<F: FieldExt> StateStore<F> {
    pub fn new() -> Self {
        Self {
            modules: RefCell::new(HashMap::new()),
            module_table: RefCell::new(Vec::new()),
            account_map: RefCell::new(BTreeMap::new()),
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

    pub fn load_resource(
        &mut self,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
    ) -> VmResult<&mut GlobalValue<F>> {
        if !self.account_map.borrow().contains_key(&addr) {
            self.account_map
                .borrow_mut()
                .insert(addr, AccountData::new());
        }
        let account_data = self.account_map.get_mut().get_mut(&addr).unwrap();

        if !account_data.data_map.contains_key(ty) {
            let ty_tag = loader.inner().type_to_type_tag(ty).map_err(|e| {
                debug!("type to type tag: {:?}", e);
                RuntimeError::new(StatusCode::InternalError)
            })?;
            match ty_tag {
                // only struct top-level value is allowed
                TypeTag::Struct(s_tag) => s_tag,
                _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
            };
            let ty_layout = loader.inner().type_to_type_layout(ty).map_err(|e| {
                debug!("type to type layout: {:?}", e);
                RuntimeError::new(StatusCode::InternalError)
            })?;
            let global_value = GlobalValue::none();
            account_data
                .data_map
                .insert(ty.clone(), (ty_layout, global_value));
        }

        Ok(account_data.global_value(ty))
    }
}

impl<F: FieldExt> Default for StateStore<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldExt> DataStore for StateStore<F> {
    fn load_resource(
        &mut self,
        _addr: MoveAccountAddress,
        _ty: &Type,
    ) -> PartialVMResult<(&mut MoveGlobalValue, Option<Option<NumBytes>>)> {
        unimplemented!()
    }

    fn load_module(&self, module_id: &ModuleId) -> VMResult<Vec<u8>> {
        let modules_ref = self.modules.borrow();
        let module = modules_ref.get(module_id).ok_or_else(|| {
            PartialVMError::new(MoveStatusCode::MISSING_DEPENDENCY)
                .with_message(format!(
                    "failed to find module {:?} in data store",
                    module_id
                ))
                .finish(Location::Undefined)
        })?;
        Ok(module.clone())
    }

    fn publish_module(
        &mut self,
        module_id: &ModuleId,
        blob: Vec<u8>,
        _is_republishing: bool,
    ) -> VMResult<()> {
        self.modules
            .borrow_mut()
            .insert(module_id.clone(), blob)
            .ok_or_else(|| {
                PartialVMError::new(MoveStatusCode::MISSING_DEPENDENCY)
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

impl<F: FieldExt> ModuleResolver for StateStore<F> {
    type Error = VMError;

    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        if self.exists_module(id)? {
            self.load_module(id).map(Some)
        } else {
            Ok(None)
        }
    }
}
