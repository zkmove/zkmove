use crate::bytecode::Instruction;
use crate::bytecodes::*;
use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::interpreter::Interpreter;
use crate::value::Value;
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
use ff::Field;
use logger::prelude::*;
use move_binary_format::file_format::Bytecode;
use move_vm_runtime::loader::Function;
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

    pub fn execute<CS>(&mut self, cs: &mut CS, interp: &mut Interpreter<E>) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        let code = self.function.code();
        let mut i = 0u32;
        for instruction in &code[self.pc as usize..] {
            debug!("step #{}, instruction {:?}", i, instruction);
            cs.push_namespace(|| format!("#{}", i));

            match instruction {
                Bytecode::LdU8(v) => LdU8(*v).execute(cs, &mut self.locals, interp),
                Bytecode::LdU64(v) => LdU64(*v).execute(cs, &mut self.locals, interp),
                Bytecode::LdU128(v) => LdU128(*v).execute(cs, &mut self.locals, interp),
                Bytecode::Pop => Pop.execute(cs, &mut self.locals, interp),
                Bytecode::Add => Add.execute(cs, &mut self.locals, interp),
                Bytecode::Sub => Sub.execute(cs, &mut self.locals, interp),
                Bytecode::Mul => Mul.execute(cs, &mut self.locals, interp),
                Bytecode::Ret => Ret.execute(cs, &mut self.locals, interp),
                Bytecode::CopyLoc(v) => CopyLoc(*v).execute(cs, &mut self.locals, interp),
                Bytecode::StLoc(v) => StLoc(*v).execute(cs, &mut self.locals, interp),
                Bytecode::LdTrue => LdTrue.execute(cs, &mut self.locals, interp),
                Bytecode::LdFalse => LdFalse.execute(cs, &mut self.locals, interp),
                Bytecode::BrTrue(offset) => {
                    let stack = &mut interp.stack;
                    let c = stack
                        .pop()?
                        .value()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
                    if !c.is_zero() {
                        debug!("BrTrue is called");
                        self.pc = *offset;
                    }
                    break;
                }
                Bytecode::BrFalse(offset) => {
                    let stack = &mut interp.stack;
                    let c = stack
                        .pop()?
                        .value()
                        .ok_or_else(|| RuntimeError::new(StatusCode::ValueConversionError))?;
                    if c.is_zero() {
                        debug!("BrFalse is called");
                        self.pc = *offset;
                    }
                    Ok(())
                }
                _ => unreachable!(),
            }?;

            cs.pop_namespace();
            i = i + 1;
        }
        Ok(())
    }
}
