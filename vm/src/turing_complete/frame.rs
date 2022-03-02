use crate::locals::Locals;
use crate::turing_complete::interpreter::Interpreter;
use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
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

    pub fn execute(&mut self, interp: &mut Interpreter<F>) -> VmResult<ExitStatus> {
        let code = self.function.code();
        loop {
            for instruction in &code[self.pc as usize..] {
                debug!("step #{}, instruction {:?}", interp.step, instruction);
                interp.step += 1;

                match instruction {
                    Bytecode::LdU8(v) => {
                        let constant = F::from_u64(*v as u64);
                        let value = Value::new_constant(constant, None, MoveValueType::U8)?;
                        interp.stack.push(value)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u64(*v);
                        let value = Value::new_constant(constant, None, MoveValueType::U64)?;
                        interp.stack.push(value)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        let value = Value::new_constant(constant, None, MoveValueType::U128)?;
                        interp.stack.push(value)
                    }
                    Bytecode::Pop => {
                        interp.stack.pop()?;
                        Ok(())
                    }
                    Bytecode::Add => interp.binary_op(Value::add),
                    Bytecode::Sub => interp.binary_op(Value::sub),
                    Bytecode::Mul => interp.binary_op(Value::mul),
                    Bytecode::Div => interp.binary_op(Value::div),
                    Bytecode::Mod => interp.binary_op(Value::rem),
                    Bytecode::Ret => return Ok(ExitStatus::Return),
                    Bytecode::Call(index) => return Ok(ExitStatus::Call(*index)),
                    Bytecode::CopyLoc(v) => interp.stack.push(self.locals.copy(*v as usize)?),
                    Bytecode::StLoc(v) => self.locals.store(*v as usize, interp.stack.pop()?),
                    Bytecode::MoveLoc(v) => interp.stack.push(self.locals.move_(*v as usize)?),
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        let value = Value::new_constant(constant, None, MoveValueType::Bool)?;
                        interp.stack.push(value)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        let value = Value::new_constant(constant, None, MoveValueType::Bool)?;
                        interp.stack.push(value)
                    }
                    Bytecode::BrTrue(offset) => {
                        let cond =
                            interp.stack.pop()?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if cond == F::one() {
                            self.pc = *offset;
                            break;
                        }
                        Ok(())
                    }
                    Bytecode::BrFalse(offset) => {
                        let cond =
                            interp.stack.pop()?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if cond == F::zero() {
                            self.pc = *offset;
                            break;
                        }
                        Ok(())
                    }
                    Bytecode::Branch(offset) => {
                        self.pc = *offset;
                        break;
                    }
                    Bytecode::Abort => {
                        let value =
                            interp.stack.pop()?.value().ok_or_else(|| {
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
                    Bytecode::Eq => interp.binary_op(Value::eq),
                    Bytecode::Neq => interp.binary_op(Value::neq),
                    Bytecode::And => interp.binary_op(Value::and),
                    Bytecode::Or => interp.binary_op(Value::or),
                    Bytecode::Not => interp.unary_op(Value::not),
                    _ => unreachable!(),
                }?;

                self.pc += 1;
            }
        }
    }

    pub fn print_frame(&self) {
        // currently only print bytecode of entry function
        println!("Bytecode of function {:?}:", self.function.name());
        for (i, instruction) in self.function.code().iter().enumerate() {
            println!("#{}, {:?}", i, instruction);
        }
    }
}

pub enum ExitStatus {
    Return,
    Call(FunctionHandleIndex),
}
