use move_binary_format::file_format::Visibility;
use move_binary_format::normalized::Type;
use move_binary_format::views::{
    FunctionDefinitionView, FunctionHandleView, ModuleView, StructHandleView,
};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{
        Bytecode, CompiledModule, FunctionDefinitionIndex, FunctionHandleIndex, TypeParameterIndex,
    },
};
use move_core_types::identifier::IdentStr;
use move_core_types::language_storage::ModuleId;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableGraph;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// Generate generic call graph for module's public function
pub fn generate(module_bytes: impl AsRef<[u8]>) -> HashMap<String, GenericCallGraph> {
    let module = CompiledModule::deserialize(module_bytes.as_ref()).unwrap();
    let graphs = GenericCallGraphBuilder::new(&module).build_graph();

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

pub struct GenericCallGraphBuilder<'a> {
    module: &'a CompiledModule,
    func_handle_def_map: HashMap<FunctionHandleIndex, FunctionDefinitionIndex>,
}

impl<'a> GenericCallGraphBuilder<'a> {
    pub fn new(module: &'a CompiledModule) -> Self {
        Self {
            module,
            func_handle_def_map: module
                .function_defs()
                .iter()
                .enumerate()
                .map(|(def_idx, def)| (def.function, FunctionDefinitionIndex::new(def_idx as u16)))
                .collect(),
        }
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
            let node = CallGeneric {
                node_pos: vec![def_idx as u16],
                fn_name: fun_def.name().to_string(),
                fn_type_parameters: fun_def
                    .type_parameters()
                    .iter()
                    .enumerate()
                    .map(|(i, _)| Type::TypeParameter(i as TypeParameterIndex))
                    .collect(),
            };
            let node_idx = graph.graph.add_node(Node::CallGeneric(node.clone()));

            CallVisitor {
                module: self.module,
                func_handle_def_map: self.func_handle_def_map.clone(),
                call_stack: vec![(node_idx, node)],
            }
            .visit(&mut graph);
            graphs.insert(func_def_index_of_call, graph);
        }
        graphs
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Node {
    CallGeneric(CallGeneric),
    Unpack(Unpack),
}
impl Display for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallGeneric(c) => Display::fmt(c, f),
            Self::Unpack(c) => Display::fmt(c, f),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Unpack {
    node_pos: Vec<u16>,
    struct_type: Type,
}
impl Display for Unpack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UNPACK<{}>", &self.struct_type)
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CallGeneric {
    node_pos: Vec<u16>,
    fn_name: String,
    fn_type_parameters: Vec<Type>,
}

impl Display for CallGeneric {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pos: {}\n {}",
            self.node_pos
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("/"),
            self.fn_name,
        )?;
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
    External { pc: usize, module: ModuleId },
    Internal { pc: usize },
}

impl Display for Edge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External { pc, module } => {
                write!(
                    f,
                    "external\n pc: {}\n module: {}",
                    pc,
                    module.short_str_lossless()
                )
            }
            Self::Internal { pc } => write!(f, "internal\n pc: {}", pc),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GenericCallGraph {
    graph: StableGraph<Node, Edge>,
}

impl GenericCallGraph {
    pub fn to_dot(&self) -> String {
        let dot = petgraph::dot::Dot::with_config(&self.graph, &[]);
        format!("{}", dot)
    }
}
struct CallVisitor<'a> {
    module: &'a CompiledModule,
    func_handle_def_map: HashMap<FunctionHandleIndex, FunctionDefinitionIndex>,
    call_stack: Vec<(NodeIndex, CallGeneric)>,
}

impl<'a> CallVisitor<'a> {
    fn visit(&self, call_graph: &mut GenericCallGraph) {
        let module_view = ModuleView::new(self.module);
        let (caller_node_idx, node_to_visit) = self.call_stack.last().unwrap();
        let func = module_view
            .function_definition(IdentStr::new(node_to_visit.fn_name.as_str()).unwrap())
            .unwrap();

        if let Some(code) = &func.code() {
            for (idx, (pc, instr)) in code
                .code
                .iter()
                .enumerate()
                .filter(|(_pc, c)| matches!(c, Bytecode::CallGeneric(_)))
                .enumerate()
            {
                match instr {
                    Bytecode::CallGeneric(callee_inst_idx) => {
                        let callee_si = self.module.function_instantiation_at(*callee_inst_idx);
                        let callee_actual_type_parameters: Vec<_> = self
                            .module
                            .signature_at(callee_si.type_parameters)
                            .0
                            .iter()
                            .map(|ty| {
                                Type::new(self.module, ty)
                                    .subst(node_to_visit.fn_type_parameters.as_ref())
                                //instantiation_type_parameters(ty, &node_to_visit.call_type_parameters)
                            })
                            .collect();

                        // Get the id of the definition of the function being called.
                        // Skip if the function is not defined in the current module, as we do not
                        // have mutual recursions across module boundaries.
                        if let Some(callee_idx) = self.func_handle_def_map.get(&callee_si.handle) {
                            let callee_node = CallGeneric {
                                node_pos: {
                                    let mut node_pos = node_to_visit.node_pos.clone();
                                    node_pos.push(idx as u16);
                                    node_pos
                                },
                                fn_name: FunctionDefinitionView::new(
                                    self.module,
                                    self.module.function_def_at(*callee_idx),
                                )
                                .name()
                                .to_string(),
                                fn_type_parameters: callee_actual_type_parameters.clone(),
                            };
                            // detect loop
                            // if call stack has same (caller, callee) as this (caller, callee), then it means the (caller, callee) is in loop.
                            // we can stop here, and pointer the caller back to afore callee (aka: the_caller -> afore_callee) instead of this callee
                            if let Some((_afore_caller, afore_callee)) = self
                                .call_stack
                                .iter()
                                .zip(self.call_stack.iter().skip(1))
                                .find(|((_, prev), (_, cur))| {
                                    prev.fn_name == node_to_visit.fn_name
                                        && prev.fn_type_parameters
                                            == node_to_visit.fn_type_parameters
                                        && cur.fn_name == callee_node.fn_name
                                        && cur.fn_type_parameters == callee_node.fn_type_parameters
                                })
                            {
                                call_graph.graph.add_edge(
                                    *caller_node_idx,
                                    afore_callee.0,
                                    Edge::Internal { pc },
                                );
                            } else {
                                let callee_node_index = call_graph
                                    .graph
                                    .add_node(Node::CallGeneric(callee_node.clone()));
                                call_graph.graph.add_edge(
                                    *caller_node_idx,
                                    callee_node_index,
                                    Edge::Internal { pc },
                                );

                                let next_visitor = CallVisitor {
                                    module: self.module,
                                    func_handle_def_map: self.func_handle_def_map.clone(),
                                    call_stack: {
                                        let mut call_stack = self.call_stack.clone();
                                        call_stack.push((callee_node_index, callee_node));
                                        call_stack
                                    },
                                };
                                next_visitor.visit(call_graph);
                            }
                        } else {
                            let func_handle_view = FunctionHandleView::new(
                                self.module,
                                self.module.function_handle_at(callee_si.handle),
                            );
                            let callee_node = CallGeneric {
                                node_pos: {
                                    let mut node_pos = node_to_visit.node_pos.clone();
                                    node_pos.push(idx as u16);
                                    node_pos
                                },
                                fn_name: func_handle_view.name().to_string(),
                                fn_type_parameters: callee_actual_type_parameters,
                            };
                            let callee_node_idx = call_graph
                                .graph
                                .add_node(Node::CallGeneric(callee_node.clone()));
                            call_graph.graph.add_edge(
                                *caller_node_idx,
                                callee_node_idx,
                                Edge::External {
                                    pc,
                                    module: func_handle_view.module_id(),
                                },
                            );
                        }
                    }
                    Bytecode::UnpackGeneric(sdii) => {
                        let struct_instantiation = self.module.struct_instantiation_at(*sdii);
                        let struct_handle_view = StructHandleView::new(
                            self.module,
                            self.module.struct_handle_at(
                                self.module
                                    .struct_def_at(struct_instantiation.def)
                                    .struct_handle,
                            ),
                        );
                        let callee_node = Unpack {
                            node_pos: {
                                let mut node_pos = node_to_visit.node_pos.clone();
                                node_pos.push(idx as u16);
                                node_pos
                            },
                            struct_type: Type::Struct {
                                address: *struct_handle_view.module_id().address(),
                                module: struct_handle_view.module_id().name().into(),
                                name: struct_handle_view.name().into(),
                                type_arguments: self
                                    .module
                                    .signature_at(struct_instantiation.type_parameters)
                                    .0
                                    .iter()
                                    .map(|ty| {
                                        Type::new(self.module, ty)
                                            .subst(node_to_visit.fn_type_parameters.as_ref())
                                    })
                                    .collect(),
                            },
                        };
                        let callee_node_idx =
                            call_graph.graph.add_node(Node::Unpack(callee_node.clone()));
                        call_graph.graph.add_edge(
                            *caller_node_idx,
                            callee_node_idx,
                            Edge::Internal { pc },
                        );
                    }
                    _ => {}
                }
            }
        }
    }
}

// fn instantiation_type_parameters(
//     type_actual: &SignatureToken,
//     caller_parameters: &[SignatureToken],
// ) -> SignatureToken {
//     match type_actual {
//         SignatureToken::TypeParameter(idx) => caller_parameters[*idx as usize].clone(),
//
//         SignatureToken::Bool
//         | SignatureToken::U8
//         | SignatureToken::U64
//         | SignatureToken::U128
//         | SignatureToken::Address
//         | SignatureToken::Struct(_)
//         | SignatureToken::Signer => type_actual.clone(),
//         SignatureToken::Vector(t) => SignatureToken::Vector(Box::new(
//             instantiation_type_parameters(t, caller_parameters),
//         )),
//
//         SignatureToken::StructInstantiation(sd, tys) => SignatureToken::StructInstantiation(
//             *sd,
//             tys.iter()
//                 .map(|ty| instantiation_type_parameters(ty, caller_parameters))
//                 .collect(),
//         ),
//         SignatureToken::Reference(ty) => SignatureToken::Reference(Box::new(
//             instantiation_type_parameters(ty, caller_parameters),
//         )),
//         SignatureToken::MutableReference(ty) => SignatureToken::Reference(Box::new(
//             instantiation_type_parameters(ty, caller_parameters),
//         )),
//     }
// }
