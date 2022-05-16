// Copyright (c) zkMove Authors

use crate::evaluation_chip::EvaluationChip;
use crate::frame::Frame;
use crate::instructions::Instructions;
use crate::locals::Locals;
use crate::program_block::ExitStatus;
use crate::stack::{CallStack, CondStack, EvalStack};
use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::{arithmetic::FieldExt, circuit::Layouter};
use logger::prelude::*;
use move_vm_runtime::loader::Function;
use movelang::argument::{convert_from, ScriptArguments};
use movelang::loader::MoveLoader;
use movelang::value::MoveValueType;
use std::sync::Arc;

pub struct Interpreter<F: FieldExt> {
    pub stack: EvalStack<F>,
    pub frames: CallStack<F>,
    pub conditions: CondStack<F>,
    pub step: u64,
}

impl<F: FieldExt> Interpreter<F> {
    pub fn new() -> Self {
        Self {
            stack: EvalStack::new(),
            frames: CallStack::new(),
            conditions: CondStack::new(),
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

    pub fn conditions(&mut self) -> &mut CondStack<F> {
        &mut self.conditions
    }

    fn process_arguments(
        &mut self,
        locals: &mut Locals<F>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
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
            let cell = evaluation_chip
                .load_private(
                    layouter.namespace(|| format!("load argument #{}", i)),
                    val,
                    ty.clone(),
                )
                .map_err(|e| {
                    debug!("Process arguments error: {:?}", e);
                    RuntimeError::from(e)
                })?;

            locals.store(i, Value::new_variable(cell.value(), cell.cell(), ty)?)?;
        }

        Ok(())
    }

    fn make_frame(&mut self, func: Arc<Function>) -> VmResult<Frame<F>> {
        let mut locals = Locals::new(func.local_count());
        let arg_count = func.arg_count();
        for i in 0..arg_count {
            locals.store(arg_count - i - 1, self.stack.pop()?)?;
        }
        Ok(Frame::new(0, 0, None, func, locals))
    }

    pub fn run_script(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        entry: Arc<Function>,
        args: Option<ScriptArguments>,
        arg_types: Vec<MoveValueType>,
        loader: &MoveLoader,
    ) -> VmResult<()> {
        let mut locals = Locals::new(entry.local_count());

        self.process_arguments(
            &mut locals,
            args,
            arg_types,
            evaluation_chip,
            layouter.namespace(|| format!("process arguments in step#{}", self.step)),
        )?;

        let mut frame = Frame::new(0, 0, None, entry, locals);
        frame.print_frame();
        loop {
            let status = frame.execute(
                evaluation_chip,
                layouter.namespace(|| format!("into frame in step#{}", self.step)),
                self,
            )?;
            match status {
                ExitStatus::Return => {
                    if let Some(caller_frame) = self.frames.pop() {
                        frame = caller_frame;
                        frame.current_block().add_pc();
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
                _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
            }
        }
    }
}

impl<F: FieldExt> Default for Interpreter<F> {
    fn default() -> Self {
        Self::new()
    }
}
