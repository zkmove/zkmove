use crate::static_info::bytecode::BytecodeInfo;
use crate::static_info::constant::ConstantInfo;
use crate::static_info::function::FunctionInfo;
use anyhow::Result;
use move_binary_format::file_format_common::Opcodes;
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

    pub fn used_opcodes(&self) -> Vec<Opcodes> {
        let mut used_opcodes = self
            .bytecode_info
            .values()
            .flat_map(|funcs| funcs.values())
            .flat_map(|bytecodes| bytecodes.iter().map(|b| b.opcode))
            .collect::<Vec<_>>();
        used_opcodes.sort_unstable();
        used_opcodes.dedup();
        used_opcodes
            .into_iter()
            .filter_map(|val| opcode_from_u8(val))
            .collect()
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

// TODO: move this to where Opcodes is defined.
fn opcode_from_u8(value: u8) -> Option<Opcodes> {
    match value {
        0x01 => Some(Opcodes::POP),
        0x02 => Some(Opcodes::RET),
        0x03 => Some(Opcodes::BR_TRUE),
        0x04 => Some(Opcodes::BR_FALSE),
        0x05 => Some(Opcodes::BRANCH),
        0x06 => Some(Opcodes::LD_U64),
        0x07 => Some(Opcodes::LD_CONST),
        0x08 => Some(Opcodes::LD_TRUE),
        0x09 => Some(Opcodes::LD_FALSE),
        0x0A => Some(Opcodes::COPY_LOC),
        0x0B => Some(Opcodes::MOVE_LOC),
        0x0C => Some(Opcodes::ST_LOC),
        0x0D => Some(Opcodes::MUT_BORROW_LOC),
        0x0E => Some(Opcodes::IMM_BORROW_LOC),
        0x0F => Some(Opcodes::MUT_BORROW_FIELD),
        0x10 => Some(Opcodes::IMM_BORROW_FIELD),
        0x11 => Some(Opcodes::CALL),
        0x12 => Some(Opcodes::PACK),
        0x13 => Some(Opcodes::UNPACK),
        0x14 => Some(Opcodes::READ_REF),
        0x15 => Some(Opcodes::WRITE_REF),
        0x16 => Some(Opcodes::ADD),
        0x17 => Some(Opcodes::SUB),
        0x18 => Some(Opcodes::MUL),
        0x19 => Some(Opcodes::MOD),
        0x1A => Some(Opcodes::DIV),
        0x1B => Some(Opcodes::BIT_OR),
        0x1C => Some(Opcodes::BIT_AND),
        0x1D => Some(Opcodes::XOR),
        0x1E => Some(Opcodes::OR),
        0x1F => Some(Opcodes::AND),
        0x20 => Some(Opcodes::NOT),
        0x21 => Some(Opcodes::EQ),
        0x22 => Some(Opcodes::NEQ),
        0x23 => Some(Opcodes::LT),
        0x24 => Some(Opcodes::GT),
        0x25 => Some(Opcodes::LE),
        0x26 => Some(Opcodes::GE),
        0x27 => Some(Opcodes::ABORT),
        0x28 => Some(Opcodes::NOP),
        0x29 => Some(Opcodes::EXISTS),
        0x2A => Some(Opcodes::MUT_BORROW_GLOBAL),
        0x2B => Some(Opcodes::IMM_BORROW_GLOBAL),
        0x2C => Some(Opcodes::MOVE_FROM),
        0x2D => Some(Opcodes::MOVE_TO),
        0x2E => Some(Opcodes::FREEZE_REF),
        0x2F => Some(Opcodes::SHL),
        0x30 => Some(Opcodes::SHR),
        0x31 => Some(Opcodes::LD_U8),
        0x32 => Some(Opcodes::LD_U128),
        0x33 => Some(Opcodes::CAST_U8),
        0x34 => Some(Opcodes::CAST_U64),
        0x35 => Some(Opcodes::CAST_U128),
        0x36 => Some(Opcodes::MUT_BORROW_FIELD_GENERIC),
        0x37 => Some(Opcodes::IMM_BORROW_FIELD_GENERIC),
        0x38 => Some(Opcodes::CALL_GENERIC),
        0x39 => Some(Opcodes::PACK_GENERIC),
        0x3A => Some(Opcodes::UNPACK_GENERIC),
        0x3B => Some(Opcodes::EXISTS_GENERIC),
        0x3C => Some(Opcodes::MUT_BORROW_GLOBAL_GENERIC),
        0x3D => Some(Opcodes::IMM_BORROW_GLOBAL_GENERIC),
        0x3E => Some(Opcodes::MOVE_FROM_GENERIC),
        0x3F => Some(Opcodes::MOVE_TO_GENERIC),
        0x40 => Some(Opcodes::VEC_PACK),
        0x41 => Some(Opcodes::VEC_LEN),
        0x42 => Some(Opcodes::VEC_IMM_BORROW),
        0x43 => Some(Opcodes::VEC_MUT_BORROW),
        0x44 => Some(Opcodes::VEC_PUSH_BACK),
        0x45 => Some(Opcodes::VEC_POP_BACK),
        0x46 => Some(Opcodes::VEC_UNPACK),
        0x47 => Some(Opcodes::VEC_SWAP),
        0x48 => Some(Opcodes::LD_U16),
        0x49 => Some(Opcodes::LD_U32),
        0x4A => Some(Opcodes::LD_U256),
        0x4B => Some(Opcodes::CAST_U16),
        0x4C => Some(Opcodes::CAST_U32),
        0x4D => Some(Opcodes::CAST_U256),
        _ => None,
    }
}
