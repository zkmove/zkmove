use crate::frame::{ExitStatus, Frame, Locals};
use crate::stack::{CallStack, EvalStack};
use crate::value::Value;
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use error::{RuntimeError, StatusCode, VmResult};
use logger::prelude::*;
use move_vm_runtime::loader::Function;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::value::MoveValueType;
use std::convert::TryInto;
use std::sync::Arc;

pub struct Interpreter<E: Engine> {
    pub stack: EvalStack<E>,
    pub frames: CallStack<E>,
    pub counter: u64,
}

impl<E> Interpreter<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        Self {
            stack: EvalStack::new(),
            frames: CallStack::new(),
            counter: 0,
        }
    }

    pub fn stack(&self) -> &EvalStack<E> {
        &self.stack
    }

    pub fn frames(&mut self) -> &mut CallStack<E> {
        &mut self.frames
    }

    pub fn current_frame(&mut self) -> Option<&mut Frame<E>> {
        self.frames.top()
    }

    fn process_arguments<CS>(
        &mut self,
        cs: &mut CS,
        locals: &mut Locals<E>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
    ) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
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
            let mut cs = cs.namespace(|| format!("argument #{}", i));

            let fr = match arg {
                Some(value) => {
                    let value: Value<E> = value.try_into()?;
                    value.value()
                }
                None => None,
            };
            let variable = cs
                .alloc(
                    || "variable",
                    || fr.ok_or(SynthesisError::AssignmentMissing),
                )
                .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))?;

            locals.store(i, Value::new_variable(fr, variable, ty)?)?;
        }

        Ok(())
    }

    fn make_frame(&mut self, func: Arc<Function>) -> VmResult<Frame<E>> {
        let mut locals = Locals::new(func.local_count());
        let arg_count = func.arg_count();
        for i in 0..arg_count {
            locals.store(arg_count - i - 1, self.stack.pop()?)?;
        }
        Ok(Frame::new(func, locals))
    }

    pub fn run_script<CS>(
        &mut self,
        cs: &mut CS,
        entry: Arc<Function>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        loader: &MoveLoader,
    ) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        let mut locals = Locals::new(entry.local_count());
        cs.enforce(
            || "constraint",
            |zero| zero + CS::one(),
            |zero| zero + CS::one(),
            |zero| zero + CS::one(),
        );

        self.process_arguments(cs, &mut locals, args, arg_types)?;

        let mut frame = Frame::new(entry, locals);
        frame.print_frame();
        loop {
            let status = frame.execute(cs, self)?;
            match status {
                ExitStatus::Return => {
                    if let Some(caller_frame) = self.frames.pop() {
                        frame = caller_frame;
                        frame.add_pc();
                    } else {
                        return Ok(());
                    }
                }
                ExitStatus::Call(index) => {
                    let func = loader.function_from_handle(frame.func(), index);
                    debug!("Call into function: {:?}", func.name());
                    let callee_frame = self.make_frame(func)?;
                    callee_frame.print_frame();
                    self.frames.push(frame)?;
                    frame = callee_frame;
                }
            }
        }
    }

    pub fn binary_op<CS, F>(&mut self, cs: &mut CS, op: F) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
        F: FnOnce(&mut CS, Value<E>, Value<E>) -> VmResult<Value<E>>,
    {
        let right = self.stack.pop()?;
        let left = self.stack.pop()?;

        let result = op(cs, left, right)?;
        self.stack.push(result)
    }

    pub fn unary_op<CS, F>(&mut self, cs: &mut CS, op: F) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
        F: FnOnce(&mut CS, Value<E>) -> VmResult<Value<E>>,
    {
        let operand = self.stack.pop()?;

        let result = op(cs, operand)?;
        self.stack.push(result)
    }
}

impl<E: Engine> Default for Interpreter<E> {
    fn default() -> Self {
        Self::new()
    }
}
