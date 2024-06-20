use bytes::Bytes;
use move_binary_format::access::ScriptAccess;
use move_binary_format::file_format::{CompiledScript, SignatureToken, Visibility};
use move_binary_format::normalized::Type;
use move_binary_format::views::{
    FunctionDefinitionView, FunctionHandleView, ModuleView, StructHandleView, ViewInternals,
};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, CompiledModule, FunctionDefinitionIndex, TypeParameterIndex},
};
use move_core_types::identifier::IdentStr;
use move_core_types::language_storage::ModuleId;
use move_core_types::metadata::Metadata;
use move_core_types::resolver::ModuleResolver;
use petgraph::prelude::EdgeRef;
pub use petgraph::prelude::NodeIndex;
use petgraph::prelude::StableGraph;
use petgraph::Direction;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

pub fn generate_for_script<'a, S: ModuleResolver>(
    script: &'a CompiledScript,
    s: &'a S,
) -> GenericCallGraph {
    let mut call_graph = GenericCallGraph::default();
    let caller_node_data = FuncCall {
        op: Bytecode::Nop, // use nop to represent root call
        module_id: None,
        fn_name: "main".to_string(),
        fn_type_parameters: script
            .type_parameters
            .iter()
            .enumerate()
            .map(|(i, _)| Type::TypeParameter(i as TypeParameterIndex))
            .collect(),
    };
    let caller_node_pos = vec![1];
    let caller_node = Node::new(caller_node_pos.clone(), caller_node_data.clone());
    let caller_node_index = call_graph.graph.add_node(caller_node.clone());
    let visitor = Visitor {
        expand_external: true,
        store: s,
        call_stack: vec![(caller_node_index, caller_node)],
    };
    for (idx, (pc, instr)) in script
        .code
        .code
        .iter()
        .enumerate()
        .filter(|(_pc, c)| matches!(c, Bytecode::CallGeneric(_) | Bytecode::Call(_)))
        .enumerate()
    {
        let (callee_func_handle, callee_inst_type_parameters) = match instr {
            Bytecode::Call(fh_index) => (*fh_index, vec![]),
            Bytecode::CallGeneric(callee_inst_idx) => {
                let callee_func_inst = script.function_instantiation_at(*callee_inst_idx);
                let callee_inst_type_parameters: Vec<_> = script
                    .signature_at(callee_func_inst.type_parameters)
                    .0
                    .iter()
                    .map(|ty| normalize_type(script, ty))
                    .collect();
                (callee_func_inst.handle, callee_inst_type_parameters)
            }
            _ => unreachable!(),
        };
        let callee_func_handle = script.function_handle_at(callee_func_handle);
        let module_handle = script.module_handle_at(callee_func_handle.module);

        let callee_node_data = FuncCall {
            op: instr.clone(),
            module_id: Some(ModuleId::new(
                *script.address_identifier_at(module_handle.address),
                script.identifier_at(module_handle.name).into(),
            )),
            fn_name: script.identifier_at(callee_func_handle.name).to_string(),
            fn_type_parameters: callee_inst_type_parameters
                .clone()
                .into_iter()
                .map(|t| t.subst(caller_node_data.fn_type_parameters.as_ref()))
                .collect(),
        };
        let callee_node_pos = {
            let mut node_pos = caller_node_pos.clone();
            node_pos.push(idx as u8 + 1);
            node_pos
        };
        let callee_node = Node::new(callee_node_pos, callee_node_data);
        let callee_node_index = call_graph.graph.add_node(callee_node.clone());
        call_graph
            .graph
            .add_edge(caller_node_index, callee_node_index, Edge::External { pc });
        visitor
            .push_stack(callee_node_index, callee_node)
            .visit(&mut call_graph);
    }
    call_graph
}

/// Generate generic call graph for module's public function
pub fn generate<S: ModuleResolver>(
    module_id: &ModuleId,
    s: &S,
) -> HashMap<String, GenericCallGraph> {
    let module = CompiledModule::deserialize(
        &s.get_module(module_id)
            .unwrap()
            .unwrap_or_else(|| panic!("cannot find module {:?}", module_id)),
    )
    .unwrap();
    let graphs = GenericCallGraphBuilder::new(&module, s).build_graph();
    graphs
        .into_iter()
        .map(|(idx, graph)| {
            let fd = module.function_def_at(idx);
            let fun_name = module
                .identifier_at(module.function_handle_at(fd.function).name)
                .as_str()
                .to_string();
            (fun_name, graph)
        })
        .collect()
}

pub struct GenericCallGraphBuilder<'a, S: ModuleResolver> {
    module: &'a CompiledModule,
    deps: &'a S,
}

impl<'a, S: ModuleResolver> GenericCallGraphBuilder<'a, S> {
    pub fn new(module: &'a CompiledModule, s: &'a S) -> Self {
        Self { module, deps: s }
    }

    pub fn build_graph(&mut self) -> HashMap<FunctionDefinitionIndex, GenericCallGraph> {
        let mut graphs = HashMap::default();
        for (def_idx, func_def) in
            self.module
                .function_defs()
                .iter()
                .enumerate()
                .filter(|(_, def)| {
                    !def.is_native() && def.visibility != Visibility::Private // no need to generate graph for private funcs
                })
        {
            let mut graph = GenericCallGraph::default();
            let func_def_index_of_call = FunctionDefinitionIndex::new(def_idx as u16);
            let fun_def = FunctionDefinitionView::new(self.module, func_def);
            let node_data = FuncCall {
                op: Bytecode::Nop,
                module_id: Some(fun_def.module().self_id()),
                fn_name: fun_def.name().to_string(),
                fn_type_parameters: fun_def
                    .type_parameters()
                    .iter()
                    .enumerate()
                    .map(|(i, _)| Type::TypeParameter(i as TypeParameterIndex))
                    .collect(),
            };
            let node = Node::new(vec![1], node_data.clone());
            let node_idx = graph.graph.add_node(node.clone());
            graph.head = node_idx;
            Visitor {
                expand_external: true,
                store: self.deps,
                call_stack: vec![(node_idx, node)],
            }
            .visit(&mut graph);
            graphs.insert(func_def_index_of_call, graph);
        }
        graphs
    }
}
#[derive(Debug, Clone)]
pub enum NodeInternal {
    Call(FuncCall),
    StorageOp(StorageOp),
}
#[derive(Debug, Clone)]
pub struct Node {
    node_pos: Vec<u8>,
    data: NodeInternal,
}

impl Node {
    pub fn new<D: Into<NodeInternal>>(pos: Vec<u8>, data: D) -> Self {
        Node {
            node_pos: pos,
            data: data.into(),
        }
    }
    pub fn pos(&self) -> &[u8] {
        &self.node_pos
    }
    pub fn data(&self) -> &NodeInternal {
        &self.data
    }
}
impl Display for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pos: {}\n {}",
            self.node_pos
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("/"),
            &self.data
        )
    }
}
impl Display for NodeInternal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call(c) => Display::fmt(c, f),
            Self::StorageOp(c) => Display::fmt(c, f),
        }
    }
}
impl From<StorageOp> for NodeInternal {
    fn from(d: StorageOp) -> Self {
        NodeInternal::StorageOp(d)
    }
}
impl From<FuncCall> for NodeInternal {
    fn from(d: FuncCall) -> Self {
        NodeInternal::Call(d)
    }
}
#[derive(Debug, Clone)]
pub struct StorageOp {
    pub op: Bytecode, // only: Exist, MoveTo,MoveFrom,BorrowGlobal,MutBorrowGlobal
    pub struct_type: Type,
    pub inst_struct_type: Type,
}
impl StorageOp {
    pub fn operand(&self) -> u16 {
        match &self.op {
            Bytecode::ExistsGeneric(t) => t.0,
            Bytecode::MoveToGeneric(t) => t.0,
            Bytecode::MoveFromGeneric(t) => t.0,
            Bytecode::MutBorrowGlobalGeneric(t) => t.0,
            Bytecode::ImmBorrowGlobalGeneric(t) => t.0,
            _ => unreachable!(),
        }
    }
}
impl Display for StorageOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}<{}>", &self.op, &self.struct_type)
    }
}
#[derive(Debug, Clone)]
pub struct FuncCall {
    op: Bytecode,
    pub module_id: Option<ModuleId>,
    pub fn_name: String,
    pub fn_type_parameters: Vec<Type>,
}
impl FuncCall {
    pub fn is_generic(&self) -> bool {
        !self.fn_type_parameters.is_empty()
    }
    pub fn is_root_call(&self) -> bool {
        matches!(&self.op, Bytecode::Nop)
    }
    pub fn func_index(&self) -> Option<u16> {
        match &self.op {
            Bytecode::Call(idx) => Some(idx.0),
            Bytecode::CallGeneric(idx) => Some(idx.0),
            Bytecode::Nop => None,
            _ => unreachable!(),
        }
    }
}
impl Display for FuncCall {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(mid) = &self.module_id {
            write!(f, "{}::", &mid)?;
        }
        write!(f, "{}", &self.fn_name)?;
        if !self.fn_type_parameters.is_empty() {
            write!(
                f,
                "<{}>",
                self.fn_type_parameters
                    .iter()
                    .map(|t| format!("{}", t))
                    .collect::<Vec<_>>()
                    .join(",")
            )?
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Edge {
    External { pc: usize },
    Internal { pc: usize },
}

impl Edge {
    pub fn pc(&self) -> usize {
        match self {
            Self::External { pc } => *pc,
            Self::Internal { pc } => *pc,
        }
    }
}

impl Edge {
    pub fn internal(&self) -> bool {
        matches!(self, Edge::Internal { .. })
    }
}
impl Display for Edge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External { pc } => {
                write!(f, "external\n pc: {}", pc,)
            }
            Self::Internal { pc } => write!(f, "internal\n pc: {}", pc),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GenericCallGraph {
    pub head: NodeIndex,
    pub graph: StableGraph<Node, Edge>,
}

impl GenericCallGraph {
    pub fn to_dot(&self) -> String {
        let dot = petgraph::dot::Dot::with_config(&self.graph, &[]);
        format!("{}", dot)
    }
    pub fn get_next_node(&self, from: NodeIndex) -> Option<NodeIndex> {
        self.graph
            .edges_directed(from, Direction::Outgoing)
            .find_map(|edge| {
                let e = edge.weight();
                if e.internal() {
                    Some(edge.target())
                } else {
                    None
                }
            })
    }
}

#[derive(Clone)]
struct Visitor<'a, S> {
    expand_external: bool,
    store: &'a S,
    call_stack: Vec<(NodeIndex, Node)>,
}

impl<'a, S> Visitor<'a, S> {
    fn push_stack(&self, idx: NodeIndex, node: Node) -> Visitor<'a, S> {
        let mut n = Self {
            expand_external: self.expand_external,
            store: self.store,
            call_stack: self.call_stack.clone(),
        };
        n.call_stack.push((idx, node));
        n
    }
}

impl<'a, S: ModuleResolver> Visitor<'a, S> {
    fn visit(&self, call_graph: &mut GenericCallGraph) {
        let (
            caller_node_idx,
            Node {
                node_pos: caller_node_pos,
                data: node_to_visit,
            },
        ) = self.call_stack.last().unwrap();
        let node_to_visit = match node_to_visit {
            NodeInternal::Call(t) => t,
            _ => unreachable!(),
        };
        let caller_module = CompiledModule::deserialize(
            &self
                .store
                .get_module(node_to_visit.module_id.as_ref().unwrap())
                .unwrap()
                .unwrap(),
        )
        .unwrap();

        let caller_code = {
            let module_view = ModuleView::new(&caller_module);
            let func = module_view
                .function_definition(IdentStr::new(node_to_visit.fn_name.as_str()).unwrap())
                .unwrap();
            func.code().cloned()
        };

        if let Some(code) = &caller_code {
            for (idx, (pc, instr)) in code
                .code
                .iter()
                .enumerate()
                .filter(|(_pc, c)| {
                    matches!(
                        c,
                        Bytecode::CallGeneric(_)
                            | Bytecode::Call(_)
                            | Bytecode::ExistsGeneric(_)
                            | Bytecode::MoveToGeneric(_)
                            | Bytecode::MoveFromGeneric(_)
                            | Bytecode::ImmBorrowGlobalGeneric(_)
                            | Bytecode::MutBorrowGlobalGeneric(_)
                    )
                })
                .enumerate()
            {
                if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                    let (callee_func_handle, callee_inst_type_parameters) = match instr {
                        Bytecode::Call(fh_index) => (*fh_index, vec![]),
                        Bytecode::CallGeneric(callee_inst_idx) => {
                            let callee_func_inst =
                                caller_module.function_instantiation_at(*callee_inst_idx);
                            let callee_inst_type_parameters: Vec<_> = caller_module
                                .signature_at(callee_func_inst.type_parameters)
                                .0
                                .iter()
                                .map(|ty| Type::new(&caller_module, ty))
                                .collect();
                            (callee_func_inst.handle, callee_inst_type_parameters)
                        }
                        _ => unreachable!(),
                    };
                    // Get the id of the definition of the function being called.
                    // Skip if the function is not defined in the current module, as we do not
                    // have mutual recursions across module boundaries.
                    let callee_func_handle = caller_module.function_handle_at(callee_func_handle);
                    let callee_func_handle_view =
                        FunctionHandleView::new(&caller_module, callee_func_handle);
                    let callee_node_data = FuncCall {
                        op: instr.clone(),
                        module_id: Some(callee_func_handle_view.module_id()),
                        fn_name: callee_func_handle_view.name().to_string(),
                        fn_type_parameters: callee_inst_type_parameters
                            .clone()
                            .into_iter()
                            .map(|t| t.subst(node_to_visit.fn_type_parameters.as_ref()))
                            .collect(),
                    };
                    // internal module function call
                    if callee_func_handle.module == caller_module.self_handle_idx() {
                        // detect loop
                        // if call stack has same (caller, callee) as this (caller, callee), then it means the (caller, callee) is in loop.
                        // we can stop here, and pointer the caller back to afore callee (aka: the_caller -> afore_callee) instead of this callee

                        let loop_detected =
                            self.call_stack
                                .iter()
                                .rev()
                                .find(|(_, node)| match &node.data {
                                    NodeInternal::Call(prev) => {
                                        prev.fn_name == callee_node_data.fn_name
                                            && prev.module_id == callee_node_data.module_id
                                            && prev.fn_type_parameters
                                                == callee_node_data.fn_type_parameters
                                        // && prev.fn_inst_type_parameters
                                        //     == callee_node_data.fn_inst_type_parameters
                                    }
                                    _ => false,
                                });

                        // let loop_detected = self
                        //     .call_stack
                        //     .iter()
                        //     .zip(self.call_stack.iter().skip(1))
                        //     .find(|((_, prev), (_, cur))| match (&prev.data, &cur.data) {
                        //         (
                        //             NodeInternal::CallGeneric(prev),
                        //             NodeInternal::CallGeneric(cur),
                        //         ) => prev == node_to_visit && cur == &callee_node_data,
                        //         _ => false,
                        //     });

                        if let Some((afore_callee_node_index, _afore_callee)) = loop_detected {
                            call_graph.graph.add_edge(
                                *caller_node_idx,
                                *afore_callee_node_index,
                                Edge::Internal { pc },
                            );
                        } else {
                            let callee_node = Node::new(
                                {
                                    let mut node_pos = caller_node_pos.clone();
                                    node_pos.push(idx as u8 + 1);
                                    node_pos
                                },
                                callee_node_data,
                            );
                            let callee_node_index = call_graph.graph.add_node(callee_node.clone());
                            call_graph.graph.add_edge(
                                *caller_node_idx,
                                callee_node_index,
                                Edge::Internal { pc },
                            );

                            self.push_stack(callee_node_index, callee_node)
                                .visit(call_graph);
                        }
                    } else {
                        // external function call
                        let callee_node = Node::new(
                            {
                                let mut node_pos = caller_node_pos.clone();
                                node_pos.push(idx as u8 + 1);
                                node_pos
                            },
                            callee_node_data,
                        );
                        let callee_node_index = call_graph.graph.add_node(callee_node.clone());
                        call_graph.graph.add_edge(
                            *caller_node_idx,
                            callee_node_index,
                            Edge::External { pc },
                        );
                        if self.expand_external {
                            self.push_stack(callee_node_index, callee_node)
                                .visit(call_graph);
                        }
                    }
                } else {
                    match instr {
                        Bytecode::ExistsGeneric(sdii)
                        | Bytecode::MoveFromGeneric(sdii)
                        | Bytecode::MoveToGeneric(sdii)
                        | Bytecode::ImmBorrowGlobalGeneric(sdii)
                        | Bytecode::MutBorrowGlobalGeneric(sdii) => {
                            let struct_instantiation = caller_module.struct_instantiation_at(*sdii);
                            let struct_handle_view = StructHandleView::new(
                                &caller_module,
                                caller_module.struct_handle_at(
                                    caller_module
                                        .struct_def_at(struct_instantiation.def)
                                        .struct_handle,
                                ),
                            );
                            let inst_struct_type = Type::Struct {
                                address: *struct_handle_view.module_id().address(),
                                module: struct_handle_view.module_id().name().into(),
                                name: struct_handle_view.name().into(),
                                type_arguments: caller_module
                                    .signature_at(struct_instantiation.type_parameters)
                                    .0
                                    .iter()
                                    .map(|ty| Type::new(&caller_module, ty))
                                    .collect(),
                            };
                            let struct_type =
                                inst_struct_type.subst(node_to_visit.fn_type_parameters.as_ref());
                            let callee_node_data = StorageOp {
                                op: instr.clone(),
                                struct_type,
                                inst_struct_type,
                            };
                            let callee_node = Node::new(
                                {
                                    let mut node_pos = caller_node_pos.clone();
                                    node_pos.push(idx as u8 + 1);
                                    node_pos
                                },
                                callee_node_data,
                            );
                            let callee_node_idx = call_graph.graph.add_node(callee_node);
                            call_graph.graph.add_edge(
                                *caller_node_idx,
                                callee_node_idx,
                                Edge::Internal { pc },
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RemoteStore {
    modules: HashMap<ModuleId, Vec<u8>>,
}

impl RemoteStore {
    // pub fn new() -> Self {
    //     Self {
    //         modules: HashMap::new(),
    //     }
    // }
    //

    pub fn add_module(&mut self, compiled_module: &CompiledModule) {
        let id = compiled_module.self_id();
        let mut bytes = vec![];
        compiled_module.serialize(&mut bytes).unwrap();
        self.modules.insert(id, bytes);
    }
}

impl ModuleResolver for RemoteStore {
    type Error = move_binary_format::errors::VMError;

    fn get_module_metadata(&self, module_id: &ModuleId) -> Vec<Metadata> {
        // fixme
        vec![]
    }

    fn get_module(&self, module_id: &ModuleId) -> Result<Option<bytes::Bytes>, Self::Error> {
        Ok(self.modules.get(module_id).cloned().map(|d| Bytes::from(d)))
    }
}

/// Create a type from signature token in script
/// the code is mostly copied from Type::new
/// Once we drop the support for script, the code can be deleted.
pub fn normalize_type(script: &CompiledScript, s: &SignatureToken) -> Type {
    use SignatureToken::*;
    match s {
        Struct(shi) => {
            let s_handle = script.struct_handle_at(*shi);
            assert!(s_handle.type_parameters.is_empty(), "A struct with N type parameters should be encoded as StructModuleInstantiation with type_arguments = [TypeParameter(1), ..., TypeParameter(N)]");
            let m_handle = script.module_handle_at(s_handle.module);
            Type::Struct {
                address: *script.address_identifier_at(m_handle.address),
                module: script.identifier_at(m_handle.name).to_owned(),
                name: script.identifier_at(s_handle.name).to_owned(),
                type_arguments: Vec::new(),
            }
        }
        StructInstantiation(shi, type_actuals) => {
            let s_handle = script.struct_handle_at(*shi);
            let m_handle = script.module_handle_at(s_handle.module);
            Type::Struct {
                address: *script.address_identifier_at(m_handle.address),
                module: script.identifier_at(m_handle.name).to_owned(),
                name: script.identifier_at(s_handle.name).to_owned(),
                type_arguments: type_actuals
                    .iter()
                    .map(|t| normalize_type(script, t))
                    .collect(),
            }
        }
        Bool => Type::Bool,
        U8 => Type::U8,
        U16 => Type::U16,
        U32 => Type::U32,
        U64 => Type::U64,
        U128 => Type::U128,
        U256 => Type::U256,
        Address => Type::Address,
        Signer => Type::Signer,
        Vector(t) => Type::Vector(Box::new(normalize_type(script, t))),
        TypeParameter(i) => Type::TypeParameter(*i),
        Reference(t) => Type::Reference(Box::new(normalize_type(script, t))),
        MutableReference(t) => Type::MutableReference(Box::new(normalize_type(script, t))),
    }
}
