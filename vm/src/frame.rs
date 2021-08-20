use crate::bytecode::Instruction;
use crate::bytecodes::*;
use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::interpreter::Interpreter;
use crate::value::Value;
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
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
    pc: u32,
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

            match instruction {
                Bytecode::Ret => {
                    return Ok(());
                }
                bytecode => {
                    cs.push_namespace(|| format!("#{}", i));
                    Self::execute_bytecode(bytecode.clone(), cs, &mut self.locals, interp)?;
                    cs.pop_namespace();
                }
            }

            i = i + 1;
        }
        Ok(())
    }

    fn execute_bytecode<CS>(
        bytecode: Bytecode,
        cs: &mut CS,
        locals: &mut Locals<E>,
        interp: &mut Interpreter<E>,
    ) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        match bytecode {
            Bytecode::LdU8(v) => LdU8(v).execute(cs, locals, interp),
            Bytecode::LdU64(v) => LdU64(v).execute(cs, locals, interp),
            Bytecode::LdU128(v) => LdU128(v).execute(cs, locals, interp),
            Bytecode::Pop => Pop.execute(cs, locals, interp),
            Bytecode::Add => Add.execute(cs, locals, interp),
            Bytecode::Sub => Sub.execute(cs, locals, interp),
            Bytecode::Mul => Mul.execute(cs, locals, interp),
            Bytecode::Ret => Ret.execute(cs, locals, interp),
            Bytecode::CopyLoc(v) => CopyLoc(v).execute(cs, locals, interp),
            Bytecode::StLoc(v) => StLoc(v).execute(cs, locals, interp),
            Bytecode::LdTrue => LdTrue.execute(cs, locals, interp),
            Bytecode::LdFalse => LdFalse.execute(cs, locals, interp),

            _ => unreachable!(),
        }
    }
}
