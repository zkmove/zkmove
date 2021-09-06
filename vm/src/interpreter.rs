use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::frame::{Frame, Locals};
use crate::stack::{CallStack, EvalStack};
use crate::value::Value;
use bellman::pairing::Engine;
use bellman::{ConstraintSystem, SynthesisError};
use move_vm_runtime::loader::Function;
use movelang::argument::{MoveValueType, ScriptArguments};
use std::convert::TryInto;
use std::sync::Arc;

pub struct Interpreter<E: Engine> {
    pub stack: EvalStack<E>,
    pub frames: CallStack<E>,
}

impl<E> Interpreter<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        Self {
            stack: EvalStack::new(),
            frames: CallStack::new(),
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

    pub fn run_script<CS>(
        &mut self,
        cs: &mut CS,
        entry: Arc<Function>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
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

        let mut frame = Frame::new(entry, locals);
        frame.print_frame();
        frame.execute(cs, self)?;
        Ok(())
    }
}
