// Copyright (c) zkMove Authors

use crate::frame::{ExitStatus, Frame};
use crate::locals::Locals;
use crate::stack::{CallStack, EvalStack};
use error::VmResult;
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_vm_runtime::loader::Function;
use movelang::argument::{convert_from, ScriptArguments};
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::value::MoveValueType;
use std::sync::Arc;
use types::value::Value;
use vm_circuit::circuit_inputs::execution_steps::ExecutionStep;
use vm_circuit::circuit_inputs::rw_operations::RWOperation;

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

    pub fn run_script(
        &mut self,
        entry: Arc<Function>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        loader: &MoveLoader,
        data_store: &mut StateStore,
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
                        return Ok(());
                    }
                }
                ExitStatus::Call(index, mut execution_step) => {
                    let call_index = self.frames.size();
                    let func = loader.function_from_handle(frame.func(), index);
                    execution_step.auxiliary = Some(Value::u64(func.arg_count() as u64, None)?);
                    execution_step.call_index = call_index;
                    debug!("step #{}, {:?}", self.step, execution_step);
                    exec_steps.push(execution_step);
                    self.step += 1;
                    debug!("Call into function: {:?}", func.name());
                    let callee_frame = self.make_frame(func, call_index + 1, rw_operations)?;
                    callee_frame.print_frame();
                    self.frames.push(frame)?;
                    frame = callee_frame;
                }
            }
        }
    }

    pub fn binary_op<Fn>(&mut self, op: Fn, rw_operations: &mut Vec<RWOperation<F>>) -> VmResult<()>
    where
        Fn: FnOnce(Value<F>, Value<F>) -> VmResult<Value<F>>,
    {
        let right = self.stack.pop(rw_operations)?;
        let left = self.stack.pop(rw_operations)?;

        let result = op(left, right)?;
        self.stack.push(result, rw_operations)
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
        step.auxiliary = Some(aux);
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
}

impl<F: FieldExt> Default for Interpreter<F> {
    fn default() -> Self {
        Self::new()
    }
}
