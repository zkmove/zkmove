use itertools::Itertools;
use move_binary_format::access::ModuleAccess;
use move_binary_format::file_format::{
    Bytecode, CompiledScript, FunctionHandleIndex, StructHandleIndex,
};

use move_binary_format::CompiledModule;
use move_core_types::language_storage::ModuleId;
use movelang::generic_call_graph::{
    generate_for_script, GenericCallGraph, NodeInternal, RemoteStore,
};
use petgraph::prelude::{EdgeRef, NodeIndex};
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct CallTraceTable(pub(crate) Vec<CallTrace>);

#[derive(Clone, Default, PartialEq, Debug, Eq, Hash)]
pub struct CallTrace {
    pub caller_id: u128,
    pub caller_module: u64,
    pub caller_function: u16,
    pub caller_pc: u64,

    pub callee_id: u128,
    pub callee_module: u64,
    pub callee_function: u16,
    pub callee_pc: u64,
}

impl From<(CompiledScript, Vec<CompiledModule>)> for CallTraceTable {
    fn from((script, deps): (CompiledScript, Vec<CompiledModule>)) -> Self {
        CallTraceTable(generate(&script, &deps))
    }
}
impl<'a> From<(&'a CompiledScript, &'a [CompiledModule])> for CallTraceTable {
    fn from((script, deps): (&'a CompiledScript, &'a [CompiledModule])) -> Self {
        CallTraceTable(generate(script, deps))
    }
}

fn generate(script: &CompiledScript, deps: &[CompiledModule]) -> Vec<CallTrace> {
    let mut store = RemoteStore::default();
    deps.iter().for_each(|dep| store.add_module(dep));
    let trace_graph = generate_for_script(script, &store);
    let name_mapping = NameToIdxMapping::build(deps);
    TraceBuilder::default()
        .build(&trace_graph)
        .into_iter()
        .map(|t| {
            let (caller_module, caller_function) =
                name_mapping.map_fn_name(t.caller_module.as_ref(), &t.caller_function);
            let (callee_module, callee_function) =
                name_mapping.map_fn_name(t.callee_module.as_ref(), &t.callee_function);
            CallTrace {
                caller_id: pos_to_id(&t.caller_id),
                caller_module,
                caller_function: caller_function.0,
                caller_pc: t.caller_pc as u64,
                callee_id: pos_to_id(&t.callee_id),
                callee_module,
                callee_function: callee_function.0,
                callee_pc: t.callee_pc as u64,
            }
        })
        .collect()
}

pub struct NameToIdxMapping {
    module_names: HashMap<String, usize>,
    fn_names: HashMap<String, HashMap<String, FunctionHandleIndex>>,
    struct_names: HashMap<String, HashMap<String, StructHandleIndex>>,
}

impl NameToIdxMapping {
    pub fn build(deps: &[CompiledModule]) -> Self {
        let mut module_names = HashMap::default();
        let mut fn_names = HashMap::new();
        let mut struct_names = HashMap::new();
        for (idx, dep) in deps.iter().enumerate() {
            module_names.insert(dep.name().to_string(), idx + 1);
            fn_names.insert(
                dep.name().to_string(),
                dep.function_defs()
                    .iter()
                    .map(|fn_def| {
                        let fn_name = dep
                            .identifier_at(dep.function_handle_at(fn_def.function).name)
                            .to_string();
                        (fn_name, fn_def.function)
                    })
                    .collect(),
            );
            struct_names.insert(
                dep.name().to_string(),
                dep.struct_defs()
                    .iter()
                    .map(|struct_def| {
                        let struct_name = dep
                            .identifier_at(dep.struct_handle_at(struct_def.struct_handle).name)
                            .to_string();
                        (struct_name, struct_def.struct_handle)
                    })
                    .collect(),
            );
        }
        Self {
            module_names,
            fn_names,
            struct_names,
        }
    }
    /// TODO: consider module address
    pub fn map_fn_name(
        &self,
        module_id: Option<&ModuleId>,
        fn_name: &FunctionName,
    ) -> (u64, FunctionHandleIndex) {
        match module_id {
            Some(mid) => {
                let m_idx = self
                    .module_names
                    .get(mid.name().as_str())
                    .cloned()
                    .unwrap_or(0) as u64;
                let f_idx = self
                    .fn_names
                    .get(mid.name().as_str())
                    .and_then(|t| {
                        if let FunctionName::General(fn_name) = fn_name {
                            t.get(fn_name)
                        } else {
                            None
                        }
                    })
                    .cloned()
                    .unwrap_or(FunctionHandleIndex(0));
                (m_idx, f_idx)
            }
            // treat script as `0`
            None => {
                let fn_index = match fn_name {
                    FunctionName::ExistsGeneric => EXISTS_GENERIC_AS_FIELD,
                    FunctionName::MoveToGeneric => MOVE_TO_GENERIC_AS_FIELD,
                    FunctionName::MoveFromGeneric => MOVE_FROM_GENERIC_AS_FIELD,
                    FunctionName::ImmBorrowGlobalGeneric => IMM_BORROW_GLOBAL_GENERIC_AS_FIELD,
                    FunctionName::MutBorrowGlobalGeneric => MUT_BORROW_GLOBAL_GENERIC_AS_FIELD,
                    FunctionName::General(_) => 0,
                };
                (0, FunctionHandleIndex(fn_index as u16))
            }
        }
    }
    /// TODO: consider module address
    pub fn map_struct_name(&self, module_id: &ModuleId, name: &str) -> (u64, StructHandleIndex) {
        let m_idx = self
            .module_names
            .get(module_id.name().as_str())
            .cloned()
            .unwrap_or(0) as u64;
        let s_idx = self
            .struct_names
            .get(module_id.name().as_str())
            .and_then(|t| t.get(name))
            .cloned()
            .unwrap_or(StructHandleIndex(0));
        (m_idx, s_idx)
    }
}

#[derive(Clone, Default, PartialEq, Debug, Eq, Hash)]
struct CallTraceInner {
    caller_id: Vec<u8>,
    caller_module: Option<ModuleId>,
    caller_function: FunctionName,
    caller_pc: usize,

    callee_id: Vec<u8>,
    callee_module: Option<ModuleId>,
    callee_function: FunctionName,
    callee_pc: usize,
}

#[derive(Default, Debug)]
pub(crate) struct TraceBuilder {
    traces: HashSet<CallTraceInner>,
}

impl TraceBuilder {
    fn build(mut self, graph: &GenericCallGraph) -> Vec<CallTraceInner> {
        self.generate(graph, 0, graph.head);
        self.traces
            .into_iter()
            .sorted_by_key(|t| (t.caller_id.clone(), t.callee_id.clone()))
            .collect()
    }
    fn generate(
        &mut self,
        graph: &GenericCallGraph,
        caller_pc: usize,
        caller_node_index: NodeIndex,
    ) {
        let caller_node = graph.graph.node_weight(caller_node_index).unwrap();
        for edge in graph
            .graph
            .edges_directed(caller_node_index, Direction::Outgoing)
        {
            let target = edge.target();
            let target_node = graph.graph.node_weight(target).unwrap();
            if let NodeInternal::CallGeneric(caller) = caller_node.data() {
                match target_node.data() {
                    NodeInternal::CallGeneric(callee) => {
                        let t = CallTraceInner {
                            caller_id: caller_node.pos().to_vec(),
                            caller_module: caller.module_id.clone(),
                            caller_function: caller.fn_name.clone().into(),
                            caller_pc: caller_pc as usize,
                            callee_id: target_node.pos().to_vec(),
                            callee_module: callee.module_id.clone(),
                            callee_function: callee.fn_name.clone().into(),
                            callee_pc: edge.weight().pc(),
                        };
                        if !self.traces.contains(&t) {
                            self.traces.insert(t);
                            self.generate(graph, edge.weight().pc(), target);
                        }
                    }
                    NodeInternal::StorageOp(unpack) => {
                        let t = CallTraceInner {
                            caller_id: caller_node.pos().to_vec(),
                            caller_module: caller.module_id.clone(),
                            caller_function: caller.fn_name.clone().into(),
                            caller_pc: caller_pc as usize,
                            callee_id: target_node.pos().to_vec(),
                            callee_module: None,
                            callee_function: unpack.op.clone().into(),
                            callee_pc: edge.weight().pc(),
                        };
                        self.traces.insert(t);
                    }
                }
            }
        }
    }
}

pub fn pos_to_id(pos: &[u8]) -> u128 {
    debug_assert!(pos.len() <= 128 / 8);
    let mut data = [0u8; 16];
    data[0..pos.len()].copy_from_slice(pos);
    u128::from_le_bytes(data)
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FunctionName {
    ExistsGeneric,
    MoveToGeneric,
    MoveFromGeneric,
    ImmBorrowGlobalGeneric,
    MutBorrowGlobalGeneric,
    General(String),
}
impl From<String> for FunctionName {
    fn from(s: String) -> Self {
        FunctionName::General(s)
    }
}

impl Default for FunctionName {
    fn default() -> Self {
        Self::General(String::default())
    }
}
pub const EXISTS_GENERIC_AS_FIELD: u16 = 1;
pub const MOVE_TO_GENERIC_AS_FIELD: u16 = 2;
pub const MOVE_FROM_GENERIC_AS_FIELD: u16 = 3;
pub const IMM_BORROW_GLOBAL_GENERIC_AS_FIELD: u16 = 4;
pub const MUT_BORROW_GLOBAL_GENERIC_AS_FIELD: u16 = 5;

impl From<Bytecode> for FunctionName {
    fn from(op: Bytecode) -> Self {
        match op {
            Bytecode::MoveToGeneric(_) => FunctionName::MoveToGeneric,
            Bytecode::MoveFromGeneric(_) => FunctionName::MoveFromGeneric,
            Bytecode::ExistsGeneric(_) => FunctionName::ExistsGeneric,
            Bytecode::ImmBorrowGlobalGeneric(_) => FunctionName::ImmBorrowGlobalGeneric,
            Bytecode::MutBorrowGlobalGeneric(_) => FunctionName::MutBorrowGlobalGeneric,
            _ => unreachable!(),
        }
    }
}
