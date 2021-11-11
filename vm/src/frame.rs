use crate::r1cs;
use crate::interpreter::Interpreter;
use crate::value::{fr_to_biguint, Value};
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
use error::{RuntimeError, StatusCode, VmResult};
use ff::Field;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
use num_traits::ToPrimitive;
use std::{cell::RefCell, rc::Rc, sync::Arc};

pub struct Locals<E: Engine>(Rc<RefCell<Vec<Value<E>>>>);

impl<E: Engine> Locals<E> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn copy(&self, index: usize) -> VmResult<Value<E>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => Ok(v.clone()),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(&mut self, index: usize, value: Value<E>) -> VmResult<()> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            // Todo: check ref count
            Some(_v) => {
                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(&self, index: usize) -> VmResult<Value<E>> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => Ok(std::mem::replace(v, Value::Invalid)),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

pub struct Frame<E: Engine> {
    pc: u16,
    locals: Locals<E>,
    function: Arc<Function>,
}

impl<E: Engine> Frame<E> {
    pub fn new(function: Arc<Function>, locals: Locals<E>) -> Self {
        Frame {
            pc: 0,
            locals,
            function,
        }
    }

    pub fn locals(&mut self) -> &mut Locals<E> {
        &mut self.locals
    }

    pub fn func(&self) -> &Arc<Function> {
        &self.function
    }

    pub fn add_pc(&mut self) {
        self.pc += 1;
    }

    pub fn execute<CS>(&mut self, cs: &mut CS, interp: &mut Interpreter<E>) -> VmResult<ExitStatus>
    where
        CS: ConstraintSystem<E>,
    {
        let code = self.function.code();
        loop {
            for instruction in &code[self.pc as usize..] {
                debug!("step #{}, instruction {:?}", interp.counter, instruction);
                cs.push_namespace(|| format!("#{}", interp.counter));
                interp.counter += 1;

                match instruction {
                    Bytecode::LdU8(v) => interp.stack.push(Value::u8(*v)?),
                    Bytecode::LdU64(v) => interp.stack.push(Value::u64(*v)?),
                    Bytecode::LdU128(v) => interp.stack.push(Value::u128(*v)?),
                    Bytecode::Pop => {
                        interp.stack.pop()?;
                        Ok(())
                    }
                    Bytecode::Add => interp.binary_op(cs, r1cs::add),
                    Bytecode::Sub => interp.binary_op(cs, r1cs::sub),
                    Bytecode::Mul => interp.binary_op(cs, r1cs::mul),
                    Bytecode::Div => interp.binary_op(cs, r1cs::div),
                    Bytecode::Mod => interp.binary_op(cs, r1cs::mod_),
                    Bytecode::Ret => return Ok(ExitStatus::Return),
                    Bytecode::Call(index) => return Ok(ExitStatus::Call(*index)),
                    Bytecode::CopyLoc(v) => interp.stack.push(self.locals.copy(*v as usize)?),
                    Bytecode::StLoc(v) => self.locals.store(*v as usize, interp.stack.pop()?),
                    Bytecode::MoveLoc(v) => interp.stack.push(self.locals.move_(*v as usize)?),
                    Bytecode::LdTrue => interp.stack.push(Value::bool(true)?),
                    Bytecode::LdFalse => interp.stack.push(Value::bool(false)?),
                    Bytecode::BrTrue(offset) => {
                        let cond =
                            interp.stack.pop()?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if !cond.is_zero() {
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
                        if cond.is_zero() {
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
                        let fr =
                            interp.stack.pop()?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        let error_code = fr_to_biguint(&fr)
                            .to_u64()
                            .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
                        return Err(RuntimeError::new(StatusCode::MoveAbort).with_message(
                            format!(
                                "Move bytecode {} aborted with error code {}",
                                self.function.pretty_string(),
                                error_code
                            ),
                        ));
                    }
                    Bytecode::Eq => interp.binary_op(cs, r1cs::eq),
                    Bytecode::Neq => interp.binary_op(cs, r1cs::neq),
                    Bytecode::And => interp.binary_op(cs, r1cs::and),
                    Bytecode::Or => interp.binary_op(cs, r1cs::or),
                    Bytecode::Not => interp.unary_op(cs, r1cs::not),

                    _ => unreachable!(),
                }?;

                cs.pop_namespace();
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
