// Copyright (c) zkMove Authors

use crate::frame::{ExitStatus, Frame};
use crate::locals::Locals;
use crate::stack::{CallStack, EvalStack};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::StructDefinitionIndex;
use move_vm_runtime::loader::Function;
use move_vm_types::loaded_data::runtime_types::Type;
use movelang::account_address::AccountAddress;
use movelang::argument::{convert_from, ScriptArguments};
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::utility::MoveValueType;
use movelang::value::{GlobalValue, Value};
use std::sync::Arc;
use vm_circuit::chips::execution_chip::opcode::Opcode;
use vm_circuit::witness::arith_operations::ArithOperation;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::function_calls::{EntryType, FunctionCall};
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
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let arg_type_pairs: Vec<_> = match args {
            Some(values) => values
                .as_inner()
                .iter()
                .map(|v| Some(v.clone()))
                .zip(arg_types)
                .collect(),
            None => std::iter::repeat(None).zip(arg_types).collect(),
        };

        for (i, (arg, ty)) in arg_type_pairs.into_iter().enumerate() {
            let val = match arg {
                Some(a) => {
                    let value: F = convert_from(a)?;
                    Some(value)
                }
                None => None,
            };
            locals.store(
                i,
                Value::new_variable(val, None, ty)?,
                call_index,
                rw_operations,
            )?;
        }

        Ok(())
    }

    fn make_frame(
        &mut self,
        func: Arc<Function>,
        call_index: usize,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<Frame<F>> {
        let mut locals = Locals::new(func.local_count());
        let arg_count = func.arg_count();
        for i in 0..arg_count {
            locals.store(
                arg_count - i - 1,
                self.stack.pop(rw_operations)?,
                call_index,
                rw_operations,
            )?;
        }
        Ok(Frame::new(func, locals))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_script(
        &mut self,
        entry: Arc<Function>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        loader: &MoveLoader,
        data_store: &mut StateStore<F>,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
        func_calls: &mut Vec<FunctionCall>,
        arith_operations: &mut Vec<ArithOperation>,
    ) -> VmResult<()> {
        let mut locals = Locals::new(entry.local_count());

        self.process_arguments(&mut locals, args, arg_types, 0, rw_operations)?;

        let mut frame = Frame::new(entry, locals);
        frame.print_frame();
        loop {
            let status = frame.execute(
                self,
                loader,
                data_store,
                exec_steps,
                rw_operations,
                arith_operations,
            )?;
            match status {
                ExitStatus::Return => {
                    let step_current = exec_steps
                        .last()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ShouldNotReachHere))?;
                    if let Some(caller_frame) = self.frames.pop() {
                        // record function ret
                        let next_module_index = caller_frame
                            .module_index(data_store)
                            .ok_or_else(|| RuntimeError::new(StatusCode::ModuleNotFound))?;
                        let next_function_index = caller_frame.func().index().0;
                        func_calls.push(FunctionCall {
                            type_: EntryType::RET,
                            module_index: step_current.module_index,
                            function_index: step_current.function_index,
                            pc: step_current.pc,
                            next_module_index,
                            next_function_index,
                            next_pc: caller_frame.pc() + 1, //next instruction after 'Call'
                        });

                        frame = caller_frame;
                        frame.add_pc();
                    } else {
                        let stop = ExecutionStep {
                            opcode: Opcode::Stop,
                            pc: step_current.pc,
                            stack_size: step_current.stack_size,
                            call_index: step_current.call_index,
                            locals_index: step_current.locals_index,
                            gc: step_current.gc,
                            module_index: step_current.module_index,
                            function_index: step_current.function_index,
                            auxiliary_1: step_current.auxiliary_1.clone(),
                            auxiliary_2: step_current.auxiliary_2.clone(),
                            auxiliary_3: step_current.auxiliary_3.clone(),
                            auxiliary_4: step_current.auxiliary_4.clone(),
                        };
                        exec_steps.push(stop);
                        return Ok(());
                    }
                }
                ExitStatus::Call(index, mut execution_step) => {
                    let call_index = self.frames.size();
                    let func = loader.function_from_handle(frame.func(), index);
                    execution_step.auxiliary_1 = Some(Value::u64(func.arg_count() as u64, None)?);
                    execution_step.auxiliary_2 = Some(Value::u64(index.0 as u64, None)?);
                    execution_step.call_index = call_index;
                    trace!("step #{}, {:?}", self.step, execution_step);
                    let module_index = execution_step.module_index;
                    let function_index = execution_step.function_index;
                    let pc = execution_step.pc;
                    exec_steps.push(execution_step);
                    self.step += 1;
                    trace!("Call into function: {:?}", func.name());
                    let callee_frame = self.make_frame(func, call_index + 1, rw_operations)?;

                    // record function call
                    let next_module_index = callee_frame
                        .module_index(data_store)
                        .ok_or_else(|| RuntimeError::new(StatusCode::ModuleNotFound))?;
                    let next_function_index = callee_frame.func().index().0;
                    func_calls.push(FunctionCall {
                        type_: EntryType::CALL,
                        module_index,
                        function_index,
                        pc,
                        next_module_index,
                        next_function_index,
                        next_pc: 0,
                    });

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
        sd_index: StructDefinitionIndex,
    ) -> VmResult<Value<F>> {
        Self::load_resource(data_store, loader, addr, ty)?.borrow_global(addr, sd_index)
    }
}

impl<F: FieldExt> Default for Interpreter<F> {
    fn default() -> Self {
        Self::new()
    }
}
