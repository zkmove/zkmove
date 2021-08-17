use crate::bytecodes::*;
use crate::error::VmResult;
use crate::interpreter::Interpreter;
use move_vm_runtime::loader::Function;
use crate::stack::EvalStack;
use crate::value::Value;
use bellman::pairing::Engine;
use bellman::ConstraintSystem;
use move_binary_format::file_format::Bytecode;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use crate::bytecode::Instruction;

pub struct Locals<E: Engine>(Rc<RefCell<Vec<Value<E>>>>);

impl<E: Engine> Locals<E> {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(vec![])))
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

    pub fn execute<CS>(
        &mut self,
        cs: &mut CS,
        interp: &mut Interpreter<E>,
    ) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        let code = self.function.code();
        let mut i = 0u32;
        for instruction in &code[self.pc as usize..] {
            println!("step #{}, instruction {:?}", i, instruction);

            match instruction {
                Bytecode::Ret => {
                    return Ok(());
                }
                bytecode => {
                    cs.push_namespace(|| format!("#{}", i));
                    Self::execute_bytecode(bytecode.clone(), cs, &mut interp.stack)?;
                    cs.pop_namespace();
                }
            }

            i = i + 1;
        }
        Ok(())
    }

    fn execute_bytecode<CS>(bytecode: Bytecode, cs: &mut CS, stack: &mut EvalStack<E>) -> VmResult<()>
    where
        CS: ConstraintSystem<E>,
    {
        match bytecode {
            Bytecode::LdU8(v) => LdU8(v).execute(cs, stack),
            Bytecode::LdU64(v) => LdU64(v).execute(cs, stack),
            Bytecode::LdU128(v) => LdU128(v).execute(cs, stack),
            Bytecode::Pop => Pop.execute(cs, stack),
            Bytecode::Add => Add.execute(cs, stack),
            Bytecode::Sub => Sub.execute(cs, stack),
            Bytecode::Mul => Mul.execute(cs, stack),
            Bytecode::Ret => Ret.execute(cs, stack),
            _ => unreachable!(),
        }
    }
}
