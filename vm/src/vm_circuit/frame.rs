// Copyright (c) zkMove Authors

use crate::value::Value;
use crate::vm_circuit::circuit_inputs::execution_steps::ExecutionStep;
use crate::vm_circuit::circuit_inputs::rw_operations::RWOperation;
use crate::vm_circuit::interpreter::Interpreter;
use crate::vm_circuit::locals::Locals;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
use movelang::state::StateStore;
use movelang::value::MoveValueType;
use std::sync::Arc;

pub struct Frame<F: FieldExt> {
    pc: u16,
    locals: Locals<F>,
    function: Arc<Function>,
}

impl<F: FieldExt> Frame<F> {
    pub fn new(function: Arc<Function>, locals: Locals<F>) -> Self {
        Frame {
            pc: 0,
            locals,
            function,
        }
    }

    pub fn locals(&mut self) -> &mut Locals<F> {
        &mut self.locals
    }

    pub fn func(&self) -> &Arc<Function> {
        &self.function
    }

    pub fn add_pc(&mut self) {
        self.pc += 1;
    }

    pub fn module_index(&self, data_store: &mut StateStore) -> Option<u16> {
        match self.function.module_id() {
            Some(module_id) => data_store.module_index(module_id),
            None => Some(0), // function is in the script
        }
    }

    pub fn execute(
        &mut self,
        interp: &mut Interpreter<F>,
        data_store: &mut StateStore,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<ExitStatus<F>> {
        let code = self.function.code();
        let call_index = interp.frames.size();
        let module_index = self
            .module_index(data_store)
            .ok_or_else(|| RuntimeError::new(StatusCode::ModuleNotFound))?;
        let function_index = self.function.index().0;
        loop {
            for instruction in &code[self.pc as usize..] {
                let mut execution_step = ExecutionStep {
                    opcode: instruction.clone().into(),
                    pc: self.pc,
                    stack_size: interp.stack.size(),
                    call_index,
                    locals_index: 0, // will be filled in CopyLoc, StLoc, MoveLoc
                    gc: rw_operations.len(),
                    module_index,
                    function_index,
                    auxiliary: None,
                };

                match instruction {
                    Bytecode::LdU8(v) => {
                        let constant = F::from_u128(*v as u128);
                        let value = Value::new_constant(constant, None, MoveValueType::U8)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u128(*v as u128);
                        let value = Value::new_constant(constant, None, MoveValueType::U64)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        let value = Value::new_constant(constant, None, MoveValueType::U128)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::Pop => {
                        interp.stack.pop(rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Add => interp.binary_op(Value::add, rw_operations),
                    Bytecode::Sub => interp.binary_op(Value::sub, rw_operations),
                    Bytecode::Mul => interp.binary_op(Value::mul, rw_operations),
                    Bytecode::Div => interp.binary_op_auxiliary(
                        Value::div,
                        Value::rem,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Mod => interp.binary_op_auxiliary(
                        Value::rem,
                        Value::div,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Ret => {
                        debug!("step #{}, {:?}", interp.step, execution_step);
                        exec_steps.push(execution_step);
                        interp.step += 1; // todo: remove interp.step
                        return Ok(ExitStatus::Return);
                    }
                    Bytecode::Call(index) => {
                        return Ok(ExitStatus::Call(*index, execution_step));
                    }
                    Bytecode::CopyLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        interp.stack.push(
                            self.locals.copy(*v as usize, call_index, rw_operations)?,
                            rw_operations,
                        )
                    }
                    Bytecode::StLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        self.locals.store(
                            *v as usize,
                            interp.stack.pop(rw_operations)?,
                            call_index,
                            rw_operations,
                        )
                    }
                    Bytecode::MoveLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        interp.stack.push(
                            self.locals.move_(*v as usize, call_index, rw_operations)?,
                            rw_operations,
                        )
                    }
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        let value = Value::new_constant(constant, None, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        let value = Value::new_constant(constant, None, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::BrTrue(offset) => {
                        execution_step.auxiliary = Some(Value::u64(*offset as u64, None)?);
                        let cond =
                            interp.stack.pop(rw_operations)?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if cond == F::one() {
                            debug!("step #{}, {:?}", interp.step, execution_step);
                            exec_steps.push(execution_step);
                            interp.step += 1;
                            self.pc = *offset;
                            break;
                        }
                        Ok(())
                    }
                    Bytecode::BrFalse(offset) => {
                        execution_step.auxiliary = Some(Value::u64(*offset as u64, None)?);
                        let cond =
                            interp.stack.pop(rw_operations)?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if cond == F::zero() {
                            debug!("step #{}, {:?}", interp.step, execution_step);
                            exec_steps.push(execution_step);
                            interp.step += 1;
                            self.pc = *offset;
                            break;
                        }
                        Ok(())
                    }
                    Bytecode::Branch(offset) => {
                        execution_step.auxiliary = Some(Value::u64(*offset as u64, None)?);
                        debug!("step #{}, {:?}", interp.step, execution_step);
                        exec_steps.push(execution_step);
                        interp.step += 1;
                        self.pc = *offset;
                        break;
                    }
                    Bytecode::Abort => {
                        debug!("step #{}, {:?}", interp.step, execution_step);
                        exec_steps.push(execution_step);

                        let value =
                            interp.stack.pop(rw_operations)?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        let error_code = value.get_lower_128(); // fixme should cast to u64?
                        return Err(RuntimeError::new(StatusCode::MoveAbort).with_message(
                            format!(
                                "Move bytecode {} aborted with error code {}",
                                self.function.pretty_string(),
                                error_code
                            ),
                        ));
                    }
                    Bytecode::Eq => interp.binary_op_auxiliary(
                        Value::eq,
                        Value::delta_invert,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Neq => interp.binary_op_auxiliary(
                        Value::neq,
                        Value::delta_invert,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Lt => interp.binary_op_auxiliary(
                        Value::lt,
                        Value::diff,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::And => interp.binary_op(Value::and, rw_operations),
                    Bytecode::Or => interp.binary_op(Value::or, rw_operations),
                    Bytecode::Not => interp.unary_op(Value::not, rw_operations),
                    _ => unreachable!(),
                }?;

                debug!("step #{}, {:?}", interp.step, execution_step);
                exec_steps.push(execution_step);
                interp.step += 1;
                self.pc += 1;
            }
        }
    }

    pub fn print_frame(&self) {
        // currently only print bytecode of entry function
        debug!("Bytecode of function {:?}:", self.function.name());
        for (i, instruction) in self.function.code().iter().enumerate() {
            debug!("#{}, {:?}", i, instruction);
        }
    }
}

pub enum ExitStatus<F: FieldExt> {
    Return,
    Call(FunctionHandleIndex, ExecutionStep<F>),
}
