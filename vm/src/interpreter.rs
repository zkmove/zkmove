// Copyright (c) zkMove Authors

use crate::frame::{ExitStatus, Frame};
use crate::locals::Locals;
use crate::stack::{CallStack, EvalStack};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_vm_runtime::loader::Function;
use movelang::argument::{convert_from, ScriptArguments};
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::value::MoveValueType;
use std::sync::Arc;
use types::value::Value;
use vm_circuit::chips::execution_chip::opcode::Opcode;
use vm_circuit::witness::execution_steps::ExecutionStep;
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
        data_store: &StateStore,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<()> {
        let mut locals = Locals::new(entry.local_count());

        self.process_arguments(&mut locals, args, arg_types, 0, rw_operations)?;

        let mut frame = Frame::new(entry, locals);
        frame.print_frame();
        loop {
            let status = frame.execute(self, data_store, exec_steps, rw_operations)?;
            match status {
                ExitStatus::Return => {
                    if let Some(caller_frame) = self.frames.pop() {
                        frame = caller_frame;
                        frame.add_pc();
                    } else {
                        let last = exec_steps
                            .last()
                            .ok_or_else(|| RuntimeError::new(StatusCode::ShouldNotReachHere))?;
                        let stop = ExecutionStep {
                            opcode: Opcode::Stop,
                            pc: last.pc,
                            stack_size: last.stack_size,
                            call_index: last.call_index,
                            locals_index: last.locals_index,
                            gc: last.gc,
                            module_index: last.module_index,
                            function_index: last.function_index,
                            auxiliary: last.auxiliary.clone(),
                        };
                        exec_steps.push(stop);
                        return Ok(());
                    }
                }
                ExitStatus::Call(index, mut execution_step) => {
                    let call_index = self.frames.size();
                    let func = loader.function_from_handle(frame.func(), index);
                    execution_step.auxiliary = Some(Value::u64(func.arg_count() as u64, None)?);
                    execution_step.call_index = call_index;
                    trace!("step #{}, {:?}", self.step, execution_step);
                    exec_steps.push(execution_step);
                    self.step += 1;
                    trace!("Call into function: {:?}", func.name());
                    let callee_frame = self.make_frame(func, call_index + 1, rw_operations)?;
                    callee_frame.print_frame();
                    self.frames.push(frame)?;
                    frame = callee_frame;
                }
            }
        }
    }

    // TODO: we should have better access to different types of containers that refs
    // can point to. perhaps we should encapsulate this in the frame and pass that down instead.
    pub fn binary_op<Fn>(
        &mut self,
        op: Fn,
        rw_operations: &mut Vec<RWOperation<F>>,
        locals: &mut Locals<F>,
        call_index: usize,
    ) -> VmResult<()>
    where
        Fn: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
    {
        let mut right = self.stack.pop(rw_operations)?;
        if let Value::Reference(r) = right {
            right = locals.read_ref(r.index(), call_index, rw_operations)?;
        };

        let mut left = self.stack.pop(rw_operations)?;
        if let Value::Reference(l) = left {
            left = locals.read_ref(l.index(), call_index, rw_operations)?;
        };

        let result = op(left, right)?;
        self.stack.push(result, rw_operations)
    }

    pub fn binary_op_auxiliary<Fa, Fb>(
        &mut self,
        op: Fa,
        fn_aux: Fb,
        rw_operations: &mut Vec<RWOperation<F>>,
        step: &mut ExecutionStep<F>,
        locals: &mut Locals<F>,
        call_index: usize,
    ) -> VmResult<()>
    where
        Fa: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
        Fb: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
    {
        let mut right = self.stack.pop(rw_operations)?;
        if let Value::Reference(r) = right {
            right = locals.read_ref(r.index(), call_index, rw_operations)?;
        };

        let mut left = self.stack.pop(rw_operations)?;
        if let Value::Reference(l) = left {
            left = locals.read_ref(l.index(), call_index, rw_operations)?;
        };

        let result = op(left.clone(), right.clone())?;
        self.stack.push(result, rw_operations)?;

        let aux = fn_aux(left, right)?;
        step.auxiliary = Some(aux);
        Ok(())
    }

    pub fn unary_op<Fn>(
        &mut self,
        op: Fn,
        rw_operations: &mut Vec<RWOperation<F>>,
        locals: &mut Locals<F>,
        call_index: usize,
    ) -> VmResult<()>
    where
        Fn: FnOnce(Value<F>) -> VmResult<Value<F>>,
    {
        let mut operand = self.stack.pop(rw_operations)?;
        if let Value::Reference(o) = operand {
            operand = locals.read_ref(o.index(), call_index, rw_operations)?;
        };

        let result = op(operand)?;
        self.stack.push(result, rw_operations)
    }
}

impl<F: FieldExt> Default for Interpreter<F> {
    fn default() -> Self {
        Self::new()
    }
}
