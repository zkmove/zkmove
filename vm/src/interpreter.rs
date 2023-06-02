// Copyright (c) zkMove Authors

use crate::frame::{ExitStatus, Frame};
use crate::locals::Locals;
use crate::stack::{CallStack, EvalStack};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, CompiledScript};
use move_vm_runtime::loader::Function;
use move_vm_types::loaded_data::runtime_types::Type;
use movelang::account_address::AccountAddress;
use movelang::argument::{argument_type, convert_from, ScriptArguments, Signer};
use movelang::generic_call_graph::{generate_for_script, Node, NodeInternal};
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::utility::MoveValueType;
use movelang::value::{GlobalRef, GlobalResourceDefIndex, GlobalValue, Value};
use petgraph::prelude::NodeIndex;

use std::sync::Arc;
use vm_circuit::chips::execution_chip::opcode::Opcode;

use vm_circuit::witness::call_trace_table::pos_to_id;
use vm_circuit::witness::execution_steps::ExecutionStep;

use vm_circuit::witness::input_type_elements::GenericTypeMaterialization;
use vm_circuit::witness::rw_operations::RWOperation;

pub struct Interpreter<F: FieldExt> {
    pub stack: EvalStack<F>,
    pub frames: CallStack<F>,
    pub step: u64,
}

impl<F: FieldExt> Interpreter<F> {
    pub fn new() -> Self {
        Self {
            stack: EvalStack::new(),
            frames: CallStack::new(),
            step: 0,
        }
    }

    pub fn stack(&self) -> &EvalStack<F> {
        &self.stack
    }

    pub fn frames(&mut self) -> &mut CallStack<F> {
        &mut self.frames
    }

    pub fn current_frame(&mut self) -> Option<&mut Frame<F>> {
        self.frames.top()
    }

    fn process_arguments(
        &mut self,
        locals: &mut Locals<F>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        // check arguments numbers
        let mut signer_and_args = Vec::new();
        if let Some(s) = signer {
            signer_and_args.push(s.into_inner());
        }
        if let Some(args) = args {
            signer_and_args.append(&mut args.into_inner());
        }
        if arg_types.len() != signer_and_args.len() {
            return Err(RuntimeError::new(StatusCode::WrongArgumentsNumber));
        }

        // check arguments types and store locals
        for i in 0..signer_and_args.len() {
            let expect_type = &arg_types[i];
            let arg = &signer_and_args[i];
            let arg_type = argument_type(arg)?;

            if arg_type != *expect_type {
                if *expect_type == MoveValueType::Signer && arg_type == MoveValueType::Address {
                    // it's signer's address, do nothing
                } else {
                    return Err(
                        RuntimeError::new(StatusCode::ArgumentsTypeMismatch).with_message(format!(
                            "script argument type {:?}, expect type {:?}",
                            arg_type, expect_type
                        )),
                    );
                }
            }

            let arg_value = convert_from(arg.clone())?;
            locals.store(
                i,
                Value::new(arg_value, expect_type.clone())?,
                frame_index,
                rw_operations,
            )?;
        }

        Ok(())
    }

    fn make_frame(
        &mut self,
        next_node_index: NodeIndex,
        next_node: Node,
        func: Arc<Function>,
        type_arguments: Vec<MoveValueType>,
        frame_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Frame<F>> {
        let locals = Locals::new(func.local_count());
        let arg_count = func.arg_count();
        let mut value = Vec::new();
        for _i in 0..arg_count {
            value.push(self.stack.pop(rw_operations)?);
        }
        for (i, item) in value.into_iter().enumerate() {
            locals.store(arg_count - i - 1, item, frame_index, rw_operations)?;
        }
        Ok(Frame::new(
            next_node_index,
            next_node,
            func,
            type_arguments,
            locals,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_script(
        &mut self,
        script: &CompiledScript,
        entry: Arc<Function>,
        type_arguments: Vec<MoveValueType>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        loader: &MoveLoader,
        data_store: &mut StateStore<F>,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
        generic_types: &mut Vec<GenericTypeMaterialization>,
    ) -> VmResult<()> {
        let generic_graph = generate_for_script(script, data_store);
        //println!("{}", generic_graph.to_dot());

        let mut locals = Locals::new(entry.local_count());

        self.process_arguments(&mut locals, signer, args, arg_types, 0, rw_operations)?;

        let mut frame = Frame::new(
            generic_graph.head,
            generic_graph
                .graph
                .node_weight(generic_graph.head)
                .cloned()
                .unwrap(),
            entry,
            type_arguments,
            locals,
        );
        frame.print_frame();
        loop {
            let status = frame.execute(
                self,
                &generic_graph,
                loader,
                data_store,
                exec_steps,
                rw_operations,
                generic_types,
            )?;
            match status {
                ExitStatus::Return => {
                    let step_current = exec_steps
                        .last()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ShouldNotReachHere))?;
                    if let Some(caller_frame) = self.frames.pop() {
                        frame = caller_frame;
                        frame.add_pc();
                    } else {
                        let stop = ExecutionStep {
                            context_id: step_current.context_id,
                            opcode: Opcode::Stop,
                            pc: step_current.pc,
                            stack_size: step_current.stack_size,
                            frame_index: step_current.frame_index,
                            locals_index: step_current.locals_index,
                            gc: step_current.gc,
                            module_index: step_current.module_index,
                            function_index: step_current.function_index,
                            auxiliary_1: step_current.auxiliary_1.clone(),
                            auxiliary_2: step_current.auxiliary_2.clone(),
                            auxiliary_3: step_current.auxiliary_3.clone(),
                            auxiliary_4: step_current.auxiliary_4.clone(),
                            auxiliary_5: step_current.auxiliary_5.clone(),
                            data: None,
                        };
                        exec_steps.push(stop);
                        return Ok(());
                    }
                }
                ExitStatus::Call(index, mut execution_step) => {
                    let frame_index = self.frames.size();
                    let func = loader.function_from_handle(frame.func(), index);
                    let next_node_index = frame.get_next_call_node(
                        &generic_graph,
                        frame.func().module_id() == func.module_id(),
                    );
                    execution_step.auxiliary_1 = Some(Value::u64(func.arg_count() as u64));
                    execution_step.auxiliary_2 = Some(Value::u64(index.0 as u64));
                    execution_step.frame_index = frame_index;
                    trace!("step #{}, {:?}", self.step, execution_step);
                    self.step += 1;
                    trace!("Call into function: {:?}", func.name());
                    let rw_op_count = rw_operations.len();
                    let callee_frame = self.make_frame(
                        next_node_index,
                        generic_graph
                            .graph
                            .node_weight(next_node_index)
                            .cloned()
                            .unwrap(),
                        func,
                        vec![],
                        frame_index + 1,
                        rw_operations,
                    )?;
                    let word_element_count = (rw_operations.len() - rw_op_count) / 2;
                    execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                    exec_steps.push(execution_step);

                    callee_frame.print_frame();
                    self.frames.push(frame)?;
                    frame = callee_frame;
                }
                ExitStatus::CallGeneric(index, mut execution_step) => {
                    let frame_index = self.frames.size();
                    let resolver = frame.func().get_resolver(loader.inner());
                    let ty_args = resolver.instantiate_generic_function(index, frame.ty_args()).map_err(|e| {
                        error!("fail to resolver.instantiate_generic_function, index: {}, ty_args: {:?}, error: {:?}", index, frame.ty_args(), e);
                        RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                    })?;

                    let func = resolver.function_from_instantiation(index);

                    let next_node_index = frame.get_next_call_node(
                        &generic_graph,
                        frame.func().module_id() == func.module_id(),
                    );

                    execution_step.frame_index = frame_index;
                    execution_step.auxiliary_1 = Some(Value::u64(func.arg_count() as u64));
                    execution_step.auxiliary_2 = Some(Value::u64(index.0 as u64));
                    trace!("step #{}, {:?}", self.step, execution_step);
                    self.step += 1;
                    trace!("Call into function: {:?}", func.name());
                    let rw_op_count = rw_operations.len();
                    let callee_frame = self.make_frame(
                        next_node_index,
                        generic_graph
                            .graph
                            .node_weight(next_node_index)
                            .cloned()
                            .unwrap(),
                        func,
                        ty_args.clone(),
                        frame_index + 1,
                        rw_operations,
                    )?;
                    let word_element_count = (rw_operations.len() - rw_op_count) / 2;
                    execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                    let caller_pc = if self.frames.size() == 0 {
                        0
                    } else {
                        self.frames.top().unwrap().pc()
                    };
                    execution_step.auxiliary_4 = Some(Value::u64(caller_pc as u64));

                    let callee_node_data = {
                        let node_data = generic_graph
                            .graph
                            .node_weight(next_node_index)
                            .unwrap()
                            .data();
                        if let NodeInternal::Call(call) = node_data {
                            call
                        } else {
                            unreachable!()
                        }
                    };
                    generic_types.push(GenericTypeMaterialization {
                        execution_step_index: exec_steps.len(),
                        op: Bytecode::CallGeneric(index),
                        frame_index: frame_index as u64,
                        instantiation_point_pc: execution_step.pc as u64,
                        instantiation_point_id: pos_to_id(
                            generic_graph
                                .graph
                                .node_weight(next_node_index)
                                .unwrap()
                                .pos(),
                        ),
                        instantiation_point_module: callee_node_data.module_id.clone(),
                        instantiation_point_function: callee_node_data.fn_name.clone().into(),
                        type_args: callee_node_data.fn_type_parameters.clone(),
                    });

                    exec_steps.push(execution_step.clone());
                    callee_frame.print_frame();
                    self.frames.push(frame)?;
                    frame = callee_frame;
                }
            }
        }
    }

    pub fn binary_op<Fn>(
        &mut self,
        op: Fn,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<MoveValueType>
    where
        Fn: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
    {
        let right = self.stack.pop(rw_operations)?;
        let left = self.stack.pop(rw_operations)?;
        let result = op(left, right)?;
        let ty = result.ty();
        self.stack.push(result, rw_operations)?;
        Ok(ty)
    }

    pub fn binary_op_auxiliary<Fa, Fb>(
        &mut self,
        op: Fa,
        fn_aux: Fb,
        rw_operations: &mut Vec<RWOperation<F>>,
        step: &mut ExecutionStep<F>,
    ) -> VmResult<()>
    where
        Fa: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
        Fb: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
    {
        let right = self.stack.pop(rw_operations)?;
        let left = self.stack.pop(rw_operations)?;
        let result = op(left.clone(), right.clone())?;
        self.stack.push(result, rw_operations)?;

        let aux = fn_aux(left, right)?;
        step.auxiliary_1 = Some(aux);
        Ok(())
    }

    pub fn unary_op<Fn>(&mut self, op: Fn, rw_operations: &mut Vec<RWOperation<F>>) -> VmResult<()>
    where
        Fn: FnOnce(Value<F>) -> VmResult<Value<F>>,
    {
        let operand = self.stack.pop(rw_operations)?;
        let result = op(operand)?;
        self.stack.push(result, rw_operations)
    }

    fn load_resource<'a>(
        data_store: &'a mut StateStore<F>,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
    ) -> VmResult<&'a mut GlobalValue<F>> {
        match data_store.load_resource(loader, addr, ty) {
            Ok(gv) => Ok(gv),
            Err(e) => {
                error!(
                    "failed to load resource {:?} at {:?} from data store",
                    ty, addr
                );
                Err(e)
            }
        }
    }

    pub fn exists(
        &mut self,
        data_store: &mut StateStore<F>,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
    ) -> VmResult<bool> {
        let global_value = Self::load_resource(data_store, loader, addr, ty)?;
        global_value.exists()
    }

    pub fn move_from(
        &mut self,
        data_store: &mut StateStore<F>,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
    ) -> VmResult<Value<F>> {
        Self::load_resource(data_store, loader, addr, ty)?.move_from()
    }

    pub fn move_to(
        &mut self,
        data_store: &mut StateStore<F>,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
        resource: Value<F>,
    ) -> VmResult<()> {
        Self::load_resource(data_store, loader, addr, ty)?.move_to(resource)
    }

    pub fn borrow_global(
        &mut self,
        data_store: &mut StateStore<F>,
        loader: &MoveLoader,
        addr: AccountAddress<F>,
        ty: &Type,
        sd_index: GlobalResourceDefIndex,
    ) -> VmResult<GlobalRef<F>> {
        Self::load_resource(data_store, loader, addr, ty)?.borrow_global(addr, sd_index)
    }
}

impl<F: FieldExt> Default for Interpreter<F> {
    fn default() -> Self {
        Self::new()
    }
}
