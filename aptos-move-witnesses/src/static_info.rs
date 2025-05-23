use crate::static_info::bytecode::BytecodeInfo;
use crate::static_info::constant::ConstantInfo;
use crate::static_info::function::FunctionInfo;
use anyhow::Result;
use move_binary_format::views::FunctionHandleView;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_package::compilation::compiled_package::CompiledPackage;
use move_vm_runtime::witnessing::traced_value::ValueItems;
use move_vm_runtime::witnessing::{Footprint, Operation};
use std::collections::{BTreeMap, HashMap};
use std::iter;
use std::path::Path;

pub mod bytecode;
pub mod constant;
pub mod function;

pub struct Footprints(pub Vec<Footprint>);
impl Footprints {
    pub fn load(path: &Path) -> Result<Self> {
        let trace_contents = std::fs::read_to_string(path)?;
        let trace = serde_json::from_str::<Vec<Footprint>>(&trace_contents)?.into();
        Ok(trace)
    }
    pub fn entry(&self) -> Option<EntryInfo> {
        let first_trace = self.0.first()?;
        if let Operation::Start { entry_call } = &first_trace.data {
            let module_id = entry_call.module_id.clone()?;
            Some(EntryInfo {
                module_id,
                function_index: entry_call.function_index as u16,
                num_args: entry_call.args.len() as u8,
            })
        } else {
            None
        }
    }
    pub fn args(&self) -> Option<Vec<ValueItems>> {
        self.0.first().and_then(|first_trace| {
            if let Operation::Start { entry_call } = &first_trace.data {
                Some(entry_call.args.clone())
            } else {
                None
            }
        })
    }
}
impl From<Vec<Footprint>> for Footprints {
    fn from(footprints: Vec<Footprint>) -> Self {
        Footprints(footprints)
    }
}
#[derive(Clone, Default, Debug)]
pub struct ModuleIdMapping(HashMap<ModuleId, (u32 /*module_index*/, CompiledModule)>);

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
            mapping.insert(m.self_id(), (idx as u32, m.clone()));
        }
        ModuleIdMapping(mapping)
    }
    pub fn get_module_index(&self, module_id: &ModuleId) -> u32 {
        let (module_index, _) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        *module_index
    }
    pub fn get_module(&self, module_id: &ModuleId) -> (u32, &CompiledModule) {
        let (module_index, module) = self
            .0
            .get(module_id)
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id));
        (*module_index, module)
    }
}

#[derive(Clone, Default, Debug)]
pub struct StaticInfo {
    pub bytecode_info: BTreeMap<u32, BTreeMap<u16, Vec<BytecodeInfo>>>,
    pub function_info: Vec<FunctionInfo>,
    pub constant_info: Vec<ConstantInfo>,
    pub module_id_mapping: ModuleIdMapping,
    pub entry_module_index: u32,
    pub entry_function_index: u16,
    pub pubs_indices: Vec<usize>,
}

impl StaticInfo {
    pub fn generate(
        entry_info: EntryInfo,
        package: &CompiledPackage,
        pubs_indices: &[usize],
    ) -> Option<Self> {
        let module_id = &entry_info.module_id;
        let module_id_mapping = ModuleIdMapping::construct(module_id, package);
        let module_index = module_id_mapping.get_module_index(module_id);

        let modules = package.all_modules_map();
        let mut deps = modules
            .get_transitive_dependencies(module_id)
            .unwrap()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        deps.push(modules.get_module(module_id).unwrap().clone());

        if Self::valid_pubs_indices(pubs_indices, entry_info.num_args) {
            Some(StaticInfo {
                bytecode_info: bytecode::parse_bytecode(&module_id_mapping, &deps),
                function_info: function::parse_function(&module_id_mapping, &deps),
                constant_info: constant::parse_constant(&module_id_mapping, &deps),
                module_id_mapping,
                entry_module_index: module_index,
                entry_function_index: entry_info.function_index,
                pubs_indices: pubs_indices.to_vec(),
            })
        } else {
            None
        }
    }
    fn valid_pubs_indices(pubs_indices: &[usize], num_args: u8) -> bool {
        // Check for out-of-bounds indices
        if pubs_indices.iter().any(|&i| i >= num_args as usize) {
            return false;
        }
        // Check for duplicate indices
        let mut set = std::collections::HashSet::with_capacity(pubs_indices.len());
        pubs_indices.iter().all(|&i| set.insert(i))
    }

    pub fn get_bytecode(
        &self,
        module_index: u32,
        function_index: u16,
        pc: usize,
    ) -> Option<BytecodeInfo> {
        self.bytecode_info
            .get(&module_index)
            .and_then(|t| t.get(&function_index))
            .and_then(|v| v.get(pc))
            .cloned()
    }

    pub fn get_constant(&self, module_index: u32, constant_index: u16) -> Option<MoveValue> {
        self.constant_info
            .iter()
            .find(|c| c.module_index == module_index && c.constant_index == constant_index)
            .map(|c| c.value.clone())
    }

    /// get function `fh_idx` in the function handle table of `module_index`
    pub fn get_function(&self, module_index: u32, fh_idx: u16) -> Option<FunctionInfo> {
        self.function_info
            .iter()
            .find(|f| f.module_index == module_index && f.function_handle_index == fh_idx)
            .cloned()
    }

    pub fn entry_function(&self) -> Option<FunctionInfo> {
        self.function_info
            .iter()
            .find(|f| {
                f.module_index == self.entry_module_index
                    && f.def_module_index == self.entry_module_index
                    && f.function_index == self.entry_function_index
            })
            .cloned()
    }
}

#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub module_id: ModuleId,
    pub function_index: u16,
    pub num_args: u8,
}
impl EntryInfo {
    pub fn new(
        package: &CompiledPackage,
        module_id: &ModuleId,
        function_name: &str,
        module_id_mapping: &ModuleIdMapping,
    ) -> Self {
        let modules = package.all_modules_map();
        let module = modules.get_module(module_id).expect("Module not found");

        let fh = module
            .function_handles
            .iter()
            .find(|handle| {
                let fh_view = FunctionHandleView::new(module, handle);
                fh_view.name().as_str() == function_name
            })
            .expect("Function handle not found");

        let func_info = FunctionInfo::parse_from_handle(module, fh, &module_id_mapping);

        Self {
            module_id: module.self_id(),
            function_index: func_info.function_index,
            num_args: func_info.num_arg,
        }
    }
}
