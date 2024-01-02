// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use crate::loader::{LoadedFunctionInst, MoveLoader};
use crate::native_functions::NativeFunctions;
use crate::state::StateStore;
use error::{RuntimeError, StatusCode, VmResult};
use logger::prelude::*;
use move_binary_format::errors::PartialVMResult;
use move_binary_format::file_format::{Bytecode, CompiledScript};
use move_binary_format::CompiledModule;
use move_core_types::identifier::IdentStr;
use move_vm_runtime::loader::Function;
use move_vm_runtime::native_extensions::NativeContextExtensions;
use movelang::argument::{convert_type_tag_to_type, ScriptArguments, Signer};
use movelang::generic_call_graph::{generate, generate_for_script, GenericCallGraph};
use movelang::utility::MoveValueType;
use movelang::value::{ModuleId, TypeTag, Value};
use types::Field;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use vm_circuit::witness::arith_operations::ArithOperations;
use vm_circuit::witness::bytecode_table::BytecodeTable;
use vm_circuit::witness::call_trace_table::{pos_to_id, CallTraceTable, NameToIdxMapping};
use vm_circuit::witness::const_table::ConstantTable;
use vm_circuit::witness::execution_steps::{ExecutionData, GenericTypeData, MaterializedTypeInfo};
use vm_circuit::witness::function_calls::FunctionCalls;
use vm_circuit::witness::input_type_elements::{InputTypeElement, InputTypeElementTableData};
use vm_circuit::witness::type_instantiation_table::{
    flatten_materialized_type, map_type_name, GenericTypeInstantiationTableData,
};
use vm_circuit::witness::{CircuitConfig, ExecutionTrace, Witness};
#[cfg(not(target_arch = "wasm32"))]
use web3::transports::Http;
#[cfg(not(target_arch = "wasm32"))]
use web3::Web3;

#[allow(dead_code)]
pub struct Runtime<F: Field> {
    loader: MoveLoader,
    natives: NativeFunctions<F>,
    native_context: NativeContext,
    _marker: PhantomData<F>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
struct NativeContext {
    web3: Option<Web3<Http>>,
    tokio_rt: Option<tokio::runtime::Runtime>,
}
#[cfg(target_arch = "wasm32")]
#[derive(Default)]
struct NativeContext {
    // web3: Option<Web3<Http>>,
    // tokio_rt: Option<tokio::runtime::Runtime>,
}

impl<F: Field> Default for Runtime<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> Runtime<F> {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new_with_natives(crate::natives::make_all()),
            natives: NativeFunctions::new(crate::natives::make_all_field_version()).unwrap(),
            native_context: NativeContext::default(),
            _marker: PhantomData,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn ext_web3(mut self, web3_url: impl AsRef<str>) -> Result<Self, web3::Error> {
        let w = Web3::new(Http::new(web3_url.as_ref())?);
        self.native_context.web3 = Some(w);
        self.native_context.tokio_rt = Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?,
        );
        Ok(self)
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }
    pub fn get_natives(&self) -> &NativeFunctions<F> {
        &self.natives
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_native_context_exts(&self) -> NativeContextExtensions {
        let mut exts = NativeContextExtensions::default();
        if let Some(ext) = &self.native_context.web3 {
            exts.add(ext);
        }
        if let Some(rt) = &self.native_context.tokio_rt {
            exts.add(rt);
        }
        exts
    }
    #[cfg(target_arch = "wasm32")]
    pub fn get_native_context_exts(&self) -> NativeContextExtensions {
        NativeContextExtensions::default()
    }

    pub fn execute_entry_function(
        &self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore<F>,
    ) -> VmResult<(ExecutionTrace<F>, Option<Value<F>>)> {
        // TODO return VMResult<SerializedReturnValues>
        let (
            module,
            entry,
            LoadedFunctionInst {
                type_arguments,
                parameters: _,
                return_: _,
            },
        ) = self
            .loader
            .load_function(module_id, function_name, &ty_args, data_store)
            .map_err(|e| {
                error!("load entry function failed: {:?}", e);
                RuntimeError::new(StatusCode::EntryFunctionLoadingError)
            })?;
        let generic_graph_map = generate(&module.module().self_id(), data_store);
        let generic_graph = generic_graph_map
            .get(entry.name())
            .expect("generic graph should not be None");
        self.execute_function(
            entry,
            type_arguments,
            signer,
            args,
            data_store,
            generic_graph,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn execute_script(
        &self,
        script: CompiledScript,
        ty_args: Vec<TypeTag>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore<F>,
    ) -> VmResult<ExecutionTrace<F>> {
        let generic_graph = generate_for_script(&script, data_store);

        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;

        let (entry, type_arguments) = self
            .loader()
            .load_script(&script_bytes, &ty_args, data_store)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                RuntimeError::new(StatusCode::ScriptLoadingError)
            })?;
        trace!("script entry {:?}", entry.name());
        let (trace, ret) = self.execute_function(
            entry,
            type_arguments,
            signer,
            args,
            data_store,
            &generic_graph,
        )?;
        assert_eq!(ret, None);
        Ok(trace)
    }

    pub fn execute_function(
        &self,
        entry: Arc<Function>,
        type_arguments: Vec<MoveValueType>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore<F>,
        generic_graph: &GenericCallGraph,
    ) -> VmResult<(ExecutionTrace<F>, Option<Value<F>>)> {
        let mut interp = Interpreter::<F>::new();
        let arg_types = entry
            .parameter_types()
            .iter()
            .map(|ty| ty.subst(&type_arguments))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|e| {
                error!("arg_types unification fail. {:?}", e);
                RuntimeError::new(StatusCode::TypeMismatch)
            })?;
        let mut exec_steps = Vec::new();
        let mut rw_operations = Vec::new();
        let mut generic_types = Vec::new();
        let ret = interp.execute_function(
            entry,
            type_arguments,
            signer,
            args,
            arg_types,
            self.loader(),
            data_store,
            &self.natives,
            self.get_native_context_exts(),
            &mut exec_steps,
            &mut rw_operations,
            &mut generic_types,
            generic_graph,
        )?;
        Ok((
            ExecutionTrace {
                exec_steps,
                rw_operations,
                generic_types,
            },
            ret,
        ))
    }

    pub fn process_execution_trace(
        &self,
        ty_args: Vec<TypeTag>,
        script_opt: Option<CompiledScript>,
        entry_function: Option<(&ModuleId, &IdentStr)>,
        modules: Vec<CompiledModule>,
        mut trace: ExecutionTrace<F>,
        circuit_config: CircuitConfig,
    ) -> VmResult<Witness<F>> {
        let mapping = NameToIdxMapping::build(&modules);
        let normalized_input_type_args: Vec<_> =
            ty_args.into_iter().map(convert_type_tag_to_type).collect();
        let input_type_element_table_data = normalized_input_type_args
            .iter()
            .enumerate()
            .flat_map(|(idx, t)| flatten_materialized_type(vec![idx as u8 + 1], t, t))
            .map(|te| {
                let (m, s) = map_type_name(&mapping, &te.data);
                (pos_to_id(&te.materialized_pos), m, s.0)
            })
            .map(|(pos, module, name)| InputTypeElement {
                ty_arg_pos: pos,
                ty_arg_module: module,
                ty_arg_name: name,
            })
            .collect();

        let exec_datas: HashMap<usize, ExecutionData> = trace
            .generic_types
            .iter()
            .map(|ti| {
                let materialized_type_elements = ti
                    .type_args
                    .iter()
                    .enumerate()
                    .flat_map(|(i, inst_type)| {
                        flatten_materialized_type(
                            vec![i as u8 + 1],
                            &inst_type.subst(&normalized_input_type_args),
                            inst_type,
                        )
                    })
                    .map(|te| {
                        let (m, s) = map_type_name(&mapping, &te.data);
                        MaterializedTypeInfo {
                            inst_ty_pos: pos_to_id(&te.instantiation_pos),
                            inst_ty_pos_max: 2u128.pow(te.instantiation_pos.len() as u32 * 8),
                            referred_param_index: te.referred_ty_idx.unwrap_or(0),
                            ty_arg_pos: pos_to_id(&te.materialized_pos),
                            ty_arg_module: m,
                            ty_arg_name: s.0,
                        }
                    })
                    .collect::<Vec<_>>();
                (
                    ti.execution_step_index,
                    match ti.op {
                        Bytecode::CallGeneric(_) => ExecutionData::CallGeneric(GenericTypeData {
                            generic_types: materialized_type_elements,
                        }),
                        _ => ExecutionData::StorageOp(GenericTypeData {
                            generic_types: materialized_type_elements,
                        }),
                    },
                )
            })
            .collect();
        exec_datas.into_iter().for_each(|(idx, data)| {
            trace
                .exec_steps
                .get_mut(idx)
                .unwrap_or_else(|| panic!("exec step at {} not exist", idx))
                .data = Some(data);
        });

        if let Some(script) = script_opt {
            let arith_operations = ArithOperations::from((Some(&script), modules.as_slice())).0;
            let func_calls = FunctionCalls::from((&script, modules.as_slice())).0;
            let call_traces = CallTraceTable::from((&script, modules.as_slice()));
            let type_instantiations =
                GenericTypeInstantiationTableData::from((&script, modules.as_slice()));
            let constants = ConstantTable::from((Some(&script), modules.as_slice()));
            let bytecodes = BytecodeTable::from((script, modules));

            Ok(Witness::new(
                trace.exec_steps,
                trace.rw_operations,
                bytecodes,
                constants,
                func_calls,
                arith_operations,
                call_traces,
                type_instantiations,
                InputTypeElementTableData(input_type_element_table_data),
                circuit_config,
            ))
        } else if let Some((entry_module, entry_function_name)) = entry_function {
            let arith_operations = ArithOperations::from((None, modules.as_slice())).0;
            let func_calls =
                FunctionCalls::from((entry_module, entry_function_name, modules.as_slice())).0;
            let call_traces =
                CallTraceTable::from((entry_module, entry_function_name, modules.as_slice()));
            let type_instantiations = GenericTypeInstantiationTableData::from((
                entry_module,
                entry_function_name,
                modules.as_slice(),
            ));
            let constants = ConstantTable::from((None, modules.as_slice()));
            let bytecodes = BytecodeTable::from(modules);

            Ok(Witness::new(
                trace.exec_steps,
                trace.rw_operations,
                bytecodes,
                constants,
                func_calls,
                arith_operations,
                call_traces,
                type_instantiations,
                InputTypeElementTableData(input_type_element_table_data),
                circuit_config,
            ))
        } else {
            unreachable!()
        }
    }
}
