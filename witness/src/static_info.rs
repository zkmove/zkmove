use crate::static_info::bytecode::BytecodeInfo;
use crate::static_info::constant::ConstantInfo;
use crate::static_info::function::FunctionInfo;
use anyhow::Result;
use move_binary_format::access::ModuleAccess;
use move_binary_format::file_format::SignatureToken;
use move_binary_format::file_format_common::Opcodes;
use move_binary_format::views::FunctionHandleView;
use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::MoveValue;
use move_package::compilation::compiled_package::CompiledPackage;
use move_vm_runtime::witnessing::traced_value::ValueItems;
use move_vm_runtime::witnessing::{Footprint, Operation};
use num_traits::cast::FromPrimitive;
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
    fn get_module_with_name(&self, module_name: &str) -> Option<(u32, &CompiledModule)> {
        self.0
            .iter()
            .find_map(|(_module_id, (module_index, module))| {
                if module.self_name().as_str() == module_name {
                    Some((*module_index, module))
                } else {
                    None
                }
            })
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
    /// Whether the circuit needs the `sub_index` dimension of memory addresses.
    ///
    /// `sub_index` identifies a leaf inside a complex (struct/vector) value.
    /// It is omitted from the circuit when the package cannot produce complex
    /// values, which removes three step cells and shrinks the teardown key.
    pub needs_sub_index: bool,
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
            let bytecode_info = bytecode::parse_bytecode(&module_id_mapping, &deps);
            let function_info = function::parse_function(&module_id_mapping, &deps);
            let constant_info = constant::parse_constant(&module_id_mapping, &deps);
            let used_opcodes = Self::collect_used_opcodes(&bytecode_info);
            let needs_sub_index = used_opcodes_need_sub_index(&used_opcodes)
                || entry_params_need_sub_index(package, &entry_info)
                || (used_opcodes.contains(&Opcodes::LD_CONST)
                    && constant_info
                        .iter()
                        .any(|constant| move_value_has_complex_value(&constant.value)));
            Some(StaticInfo {
                bytecode_info,
                function_info,
                constant_info,
                module_id_mapping,
                entry_module_index: module_index,
                entry_function_index: entry_info.function_index,
                pubs_indices: pubs_indices.to_vec(),
                needs_sub_index,
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
        Self::collect_used_opcodes(&self.bytecode_info)
    }

    fn collect_used_opcodes(
        bytecode_info: &BTreeMap<u32, BTreeMap<u16, Vec<BytecodeInfo>>>,
    ) -> Vec<Opcodes> {
        let mut used_opcodes = bytecode_info
            .values()
            .flat_map(|funcs| funcs.values())
            .flat_map(|bytecodes| bytecodes.iter().map(|b| b.opcode))
            .collect::<Vec<_>>();
        used_opcodes.sort_unstable();
        used_opcodes.dedup();
        used_opcodes
            .into_iter()
            .filter_map(Opcodes::from_u8)
            .collect()
    }

    pub fn contain_zkhash(&self) -> bool {
        self.module_id_mapping
            .get_module_with_name("zkhash")
            .is_some()
    }
}

/// Opcodes that can create or consume a non-zero `sub_index` path.
///
/// A value carrying a sub-index path can only originate from packing/unpacking
/// a complex value, borrowing a field, or a vector element operation.  Opcodes
/// such as `CopyLoc`, `Call`, `ReadRef`, `WriteRef` or `Pop` only propagate
/// paths created by one of the opcodes below (or by the entry arguments / a
/// complex constant), so they do not force the sub-index cells.
pub const COMPLEX_OPCODES: &[Opcodes] = &[
    Opcodes::PACK,
    Opcodes::UNPACK,
    Opcodes::VEC_PACK,
    Opcodes::VEC_UNPACK,
    Opcodes::IMM_BORROW_FIELD,
    Opcodes::MUT_BORROW_FIELD,
    Opcodes::VEC_IMM_BORROW,
    Opcodes::VEC_MUT_BORROW,
    Opcodes::VEC_POP_BACK,
    Opcodes::VEC_PUSH_BACK,
    Opcodes::VEC_SWAP,
    Opcodes::VEC_LEN,
];

fn used_opcodes_need_sub_index(opcodes: &[Opcodes]) -> bool {
    opcodes
        .iter()
        .any(|opcode| COMPLEX_OPCODES.contains(opcode))
}

fn signature_token_has_complex_value(token: &SignatureToken) -> bool {
    match token {
        SignatureToken::Struct(_)
        | SignatureToken::StructInstantiation(_, _)
        | SignatureToken::Vector(_) => true,
        // A reference itself does not carry a sub-index path; paths to fields
        // are created by BorrowField and friends.  Type parameters are treated
        // conservatively.
        SignatureToken::TypeParameter(_) => true,
        _ => false,
    }
}

fn entry_params_need_sub_index(package: &CompiledPackage, entry_info: &EntryInfo) -> bool {
    let modules = package.all_modules_map();
    let Ok(module) = modules.get_module(&entry_info.module_id) else {
        return false;
    };
    let Some(function_def) = module.function_defs.get(entry_info.function_index as usize) else {
        return false;
    };
    let handle = module.function_handle_at(function_def.function);
    module
        .signatures
        .get(handle.parameters.0 as usize)
        .map(|signature| signature.0.iter().any(signature_token_has_complex_value))
        .unwrap_or(false)
}

fn move_value_has_complex_value(value: &MoveValue) -> bool {
    matches!(value, MoveValue::Vector(_) | MoveValue::Struct(_))
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

        let func_info = FunctionInfo::parse_from_handle(module, fh, module_id_mapping);

        Self {
            module_id: module.self_id(),
            function_index: func_info.function_index,
            num_args: func_info.num_arg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_binary_format::file_format::StructHandleIndex;

    #[test]
    fn detects_complex_opcodes() {
        assert!(used_opcodes_need_sub_index(&[Opcodes::PACK]));
        assert!(used_opcodes_need_sub_index(&[
            Opcodes::RET,
            Opcodes::VEC_POP_BACK
        ]));
        assert!(!used_opcodes_need_sub_index(&[
            Opcodes::RET,
            Opcodes::COPY_LOC,
            Opcodes::CALL
        ]));
    }

    #[test]
    fn detects_complex_signature_tokens() {
        assert!(!signature_token_has_complex_value(&SignatureToken::U64));
        assert!(!signature_token_has_complex_value(
            &SignatureToken::Reference(Box::new(SignatureToken::U64))
        ));
        assert!(signature_token_has_complex_value(&SignatureToken::Struct(
            StructHandleIndex(0)
        )));
        assert!(signature_token_has_complex_value(&SignatureToken::Vector(
            Box::new(SignatureToken::U8)
        )));
    }

    #[test]
    fn detects_complex_constants() {
        assert!(!move_value_has_complex_value(&MoveValue::U64(1)));
        assert!(move_value_has_complex_value(&MoveValue::Vector(vec![
            MoveValue::U8(1)
        ])));
    }
}
