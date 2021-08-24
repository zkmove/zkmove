use crate::error::VmResult;
use crate::frame::{Frame, Locals};
use crate::stack::{CallStack, EvalStack};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
use move_vm_runtime::loader::Function;
use movelang::argument::ScriptArguments;
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
        args: ScriptArguments,
    ) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        let mut locals = Locals::new(entry.local_count());
        for (i, arg) in args.as_inner().into_iter().enumerate() {
            locals.store(i, arg.try_into()?)?;
        }

        let mut frame = Frame::new(entry, locals);
        frame.print_frame();
        frame.execute(cs, self)?;
        Ok(())
    }
}
