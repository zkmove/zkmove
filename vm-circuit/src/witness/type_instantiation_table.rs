use crate::witness::call_trace_table::{pos_to_id, FunctionName, NameToIdxMapping};

use move_binary_format::file_format::{CompiledScript, StructDefinitionIndex};
use move_binary_format::normalized::Type;

use move_binary_format::CompiledModule;

use move_core_types::language_storage::ModuleId;
use movelang::generic_call_graph::{
    generate_for_script, GenericCallGraph, NodeInternal, RemoteStore,
};
use petgraph::prelude::{EdgeRef, NodeIndex};
use petgraph::Direction;
use std::collections::{BTreeSet, HashSet};

#[derive(Clone, Default, PartialEq, Debug, Eq)]
pub struct GenericTypeInstantiationTableData(pub(crate) Vec<GenericTypeInstantiation>);

#[derive(Clone, Default, PartialEq, Debug, Eq)]
pub struct GenericTypeInstantiation {
    pub(crate) caller_id: u128,
    pub(crate) caller_module: u64,
    pub(crate) caller_function: u16,
    pub(crate) caller_callin_pc: usize,

    pub(crate) instantiation_id: u128,

    pub(crate) instantiation_point_pc: u64,
    pub(crate) instantiation_point_module: u64,
    pub(crate) instantiation_point_function: u16,
    pub(crate) instantiation_index: u16,

    /// start from 1, 0 means no reference to ty parameter.
    pub(crate) referred_ty_idx: u16, // TODO: check if it possible for two different referred index while other infos are the same.
    pub(crate) ty_pos: u128, // type pos in little endian, such as: 1/2 -> 2 * 256+1
    pub(crate) ty_module: u64, // module index
    pub(crate) ty_name: u16, // struct handle index in the module
}

impl From<(CompiledScript, Vec<CompiledModule>)> for GenericTypeInstantiationTableData {
    fn from((script, deps): (CompiledScript, Vec<CompiledModule>)) -> Self {
        GenericTypeInstantiationTableData(generate(&script, &deps))
    }
}
impl<'a> From<(&'a CompiledScript, &'a [CompiledModule])> for GenericTypeInstantiationTableData {
    fn from((script, deps): (&'a CompiledScript, &'a [CompiledModule])) -> Self {
        GenericTypeInstantiationTableData(generate(script, deps))
    }
}

fn generate(script: &CompiledScript, deps: &[CompiledModule]) -> Vec<GenericTypeInstantiation> {
    let mut store = RemoteStore::default();
    deps.iter().for_each(|dep| store.add_module(dep));
    let trace_graph = generate_for_script(script, &store);
    let name_mapping = NameToIdxMapping::build(deps);
    TypeInstantiationBuilder::default()
        .build(&trace_graph)
        .into_iter()
        .flat_map(|fi_info| {
            let (m, f) = name_mapping.map_fn_name(
                fi_info.instantiation_point_module.as_ref(),
                &fi_info.instantiation_point_function,
            );
            let (caller_m, caller_f) = name_mapping
                .map_fn_name(fi_info.caller_module_id.as_ref(), &fi_info.caller_function);
            let pc = fi_info.instantiation_point_pc;
            let instantiation_index = fi_info.instantiation_index;
            let caller_id = pos_to_id(fi_info.caller_id.as_ref());
            let caller_callin_pc = fi_info.caller_callin_pc;
            let instantiated_callee_id = pos_to_id(fi_info.instantiation_id.as_ref());
            // let function_instantiation_index =
            //     resolver.resolve(fi_info.caller_module_id.as_ref(), caller_f, pc as usize);
            let name_mapping = &name_mapping;
            fi_info
                .ty_params
                .into_iter()
                .enumerate()
                .flat_map(|(idx, t)| flatten_type(&t, vec![idx as u8 + 1]))
                .map(move |t| {
                    let (ty_module, ty_name) = t
                        .data
                        .map(|t| map_type_name(name_mapping, &t))
                        .unwrap_or((0, StructDefinitionIndex(0)));
                    GenericTypeInstantiation {
                        caller_id,
                        caller_module: caller_m,
                        caller_function: caller_f.0,
                        caller_callin_pc,

                        instantiation_id: instantiated_callee_id,
                        instantiation_point_module: m,
                        instantiation_point_function: f.0,
                        instantiation_point_pc: pc,

                        instantiation_index,

                        referred_ty_idx: t.referred_ty_idx.unwrap_or(0),
                        ty_pos: pos_to_id(&t.pos),
                        ty_module,
                        ty_name: ty_name.0,
                    }
                })
        })
        .collect()
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct TypeInstantiationInfo {
    caller_id: Vec<u8>,
    caller_module_id: Option<ModuleId>,
    caller_function: FunctionName,
    caller_callin_pc: usize,

    instantiation_id: Vec<u8>,
    instantiation_point_module: Option<ModuleId>,
    instantiation_point_function: FunctionName,
    instantiation_point_pc: u64,

    instantiation_index: u16,
    ty_params: Vec<Type>,
}
#[derive(Default, Debug)]
pub(crate) struct TypeInstantiationBuilder {
    traces: BTreeSet<TypeInstantiationInfo>,
}

impl TypeInstantiationBuilder {
    fn build(mut self, graph: &GenericCallGraph) -> Vec<TypeInstantiationInfo> {
        let mut visited_node_indexes: HashSet<NodeIndex> = HashSet::default();
        self.generate(graph, &mut visited_node_indexes, 0, graph.head);
        self.traces.into_iter().collect()
    }
    fn generate(
        &mut self,
        graph: &GenericCallGraph,
        visited_node_indexes: &mut HashSet<NodeIndex>,
        caller_callin_pc: usize,
        caller_node_index: NodeIndex,
    ) {
        if visited_node_indexes.contains(&caller_node_index) {
            return;
        }
        visited_node_indexes.insert(caller_node_index);

        let caller_node = graph.graph.node_weight(caller_node_index).unwrap();
        for edge in graph
            .graph
            .edges_directed(caller_node_index, Direction::Outgoing)
        {
            let target = edge.target();
            let target_node = graph.graph.node_weight(target).unwrap();
            if let NodeInternal::Call(caller) = caller_node.data() {
                match target_node.data() {
                    NodeInternal::Call(callee) => {
                        let inst = TypeInstantiationInfo {
                            caller_id: caller_node.pos().to_vec(),
                            caller_module_id: caller.module_id.clone(),
                            caller_function: caller.fn_name.clone().into(),
                            caller_callin_pc,

                            instantiation_id: target_node.pos().to_vec(),
                            instantiation_point_module: callee.module_id.clone(),
                            instantiation_point_function: callee.fn_name.clone().into(),
                            instantiation_point_pc: edge.weight().pc() as u64,
                            instantiation_index: callee.func_index().unwrap_or(0),
                            ty_params: callee.fn_type_parameters.clone(),
                        };
                        self.traces.insert(inst);
                        self.generate(graph, visited_node_indexes, edge.weight().pc(), target);
                    }
                    NodeInternal::StorageOp(callee) => {
                        let inst = TypeInstantiationInfo {
                            caller_id: caller_node.pos().to_vec(),
                            caller_module_id: caller.module_id.clone(),
                            caller_function: caller.fn_name.clone().into(),
                            caller_callin_pc,

                            instantiation_id: target_node.pos().to_vec(),
                            instantiation_point_pc: edge.weight().pc() as u64,
                            instantiation_point_module: None,
                            instantiation_point_function: callee.op.clone().into(),
                            instantiation_index: callee.operand(),
                            ty_params: vec![callee.struct_type.clone()],
                        };
                        self.traces.insert(inst);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeElement {
    pos: Vec<u8>,
    referred_ty_idx: Option<u16>,
    data: Option<TypeElem>,
}
fn flatten_type(ty: &Type, pos: Vec<u8>) -> Vec<TypeElement> {
    fn flatten_inner(result: &mut Vec<TypeElement>, ty: &Type, mut pos: Vec<u8>) {
        match ty {
            Type::Struct {
                address,
                module,
                name,
                type_arguments,
            } => {
                result.push(TypeElement {
                    pos: pos.clone(),
                    referred_ty_idx: None,
                    data: Some(TypeElem::Struct {
                        module_id: ModuleId::new(*address, module.clone()),
                        name: name.to_string(),
                    }),
                });
                for (idx, sub_type) in type_arguments.iter().enumerate() {
                    flatten_inner(result, sub_type, {
                        let mut pos = pos.clone();
                        pos.push(idx as u8 + 1);
                        pos
                    });
                }
            }
            Type::TypeParameter(idx) => result.push(TypeElement {
                pos: pos.clone(),
                referred_ty_idx: Some(*idx + 1), // type index start from 1
                data: None,
            }),
            Type::Vector(inner) => {
                result.push(TypeElement {
                    pos: pos.clone(),
                    referred_ty_idx: None,
                    data: Some(TypeElem::Vector),
                });
                flatten_inner(result, inner, {
                    pos.push(1);
                    pos
                });
            }
            _ => {
                let data = match ty {
                    Type::Bool => TypeElem::Bool,
                    Type::U8 => TypeElem::U8,
                    Type::U16 => TypeElem::U16,
                    Type::U32 => TypeElem::U32,
                    Type::U64 => TypeElem::U64,
                    Type::U128 => TypeElem::U128,
                    Type::U256 => TypeElem::U256,
                    Type::Address => TypeElem::Address,
                    Type::Signer => TypeElem::Signer,
                    _ => unreachable!(),
                };
                result.push(TypeElement {
                    pos: pos.to_vec(),
                    referred_ty_idx: None,
                    data: Some(data),
                });
            }
        };
    }
    let mut result = vec![];
    flatten_inner(&mut result, ty, pos);
    result
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeElem {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    Struct { module_id: ModuleId, name: String },
    Vector,
}
pub fn map_type_name(
    mapping: &NameToIdxMapping,
    type_elem: &TypeElem,
) -> (u64, StructDefinitionIndex) {
    match type_elem {
        TypeElem::Bool => (0, StructDefinitionIndex(1)),
        TypeElem::U8 => (0, StructDefinitionIndex(2)),
        TypeElem::U16 => (0, StructDefinitionIndex(3)),
        TypeElem::U32 => (0, StructDefinitionIndex(4)),
        TypeElem::U64 => (0, StructDefinitionIndex(5)),
        TypeElem::U128 => (0, StructDefinitionIndex(6)),
        TypeElem::U256 => (0, StructDefinitionIndex(7)),
        TypeElem::Address => (0, StructDefinitionIndex(8)),
        TypeElem::Signer => (0, StructDefinitionIndex(9)),
        TypeElem::Vector => (0, StructDefinitionIndex(10)),
        TypeElem::Struct { module_id, name } => mapping.map_struct_name(module_id, name),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedTypeElement {
    pub materialized_pos: Vec<u8>,
    pub data: TypeElem,
    pub instantiation_pos: Vec<u8>,
    pub referred_ty_idx: Option<u16>,
}

/// caller must ensure, first type is materialized from the second.
pub fn flatten_materialized_type(
    pos: Vec<u8>,
    actual: &Type,
    inst: &Type,
) -> Vec<MaterializedTypeElement> {
    let materialized_type_elems = flatten_type(actual, pos.clone());
    let instantiation_type_elems = flatten_type(inst, pos);
    let mut i = 0;
    let mut results = vec![];
    for inst_type_elem in instantiation_type_elems {
        if let Some(refer) = inst_type_elem.referred_ty_idx {
            while materialized_type_elems
                .get(i)
                .filter(|e| e.pos.starts_with(&inst_type_elem.pos))
                .is_some()
            {
                results.push(MaterializedTypeElement {
                    materialized_pos: materialized_type_elems[i].pos.clone(),
                    data: materialized_type_elems[i].data.clone().unwrap(),
                    instantiation_pos: inst_type_elem.pos.clone(),
                    referred_ty_idx: Some(refer),
                });
                i += 1;
            }
        } else {
            debug_assert_eq!(&materialized_type_elems[i], &inst_type_elem);
            results.push(MaterializedTypeElement {
                materialized_pos: materialized_type_elems[i].pos.clone(),
                data: materialized_type_elems[i].data.clone().unwrap(),
                instantiation_pos: inst_type_elem.pos,
                referred_ty_idx: None,
            });
            i += 1;
        }
    }
    results
}
