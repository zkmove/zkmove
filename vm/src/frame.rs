use crate::circuit::EvaluationChip;
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
use crate::interpreter::Interpreter;
use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::{arithmetic::FieldExt, circuit::Layouter};
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
use movelang::value::MoveValueType;
use std::{cell::RefCell, rc::Rc, sync::Arc};

pub struct Locals<F: FieldExt>(Rc<RefCell<Vec<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn copy(&self, index: usize) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => Ok(v.clone()),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(&mut self, index: usize, value: Value<F>) -> VmResult<()> {
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

    pub fn move_(&self, index: usize) -> VmResult<Value<F>> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => Ok(std::mem::replace(v, Value::Invalid)),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }
}

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

    pub fn execute(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        interp: &mut Interpreter<F>,
    ) -> VmResult<ExitStatus> {
        macro_rules! load_constant {
            ($constant:expr, $ty:expr) => {{
                let value = evaluation_chip
                    .load_constant(
                        layouter.namespace(|| format!("load constant in step#{}", interp.step)),
                        $constant,
                        $ty,
                    )
                    .map_err(|e| {
                        error!("load constant failed: {:?}", e);
                        RuntimeError::new(StatusCode::SynthesisError)
                    })?;
                interp.stack.push(value)
            }};
        }

        let code = self.function.code();
        loop {
            for instruction in &code[self.pc as usize..] {
                debug!("step #{}, instruction {:?}", interp.step, instruction);
                interp.step += 1;

                match instruction {
                    Bytecode::LdU8(v) => {
                        let constant = F::from_u64(*v as u64);
                        load_constant!(constant, MoveValueType::U8)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u64(*v);
                        load_constant!(constant, MoveValueType::U64)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        load_constant!(constant, MoveValueType::U128)
                    }
                    Bytecode::Pop => {
                        interp.stack.pop()?;
                        Ok(())
                    }
                    Bytecode::Add => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .add(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                interp.conditions().top(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    Bytecode::Sub => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .sub(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                interp.conditions().top(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    Bytecode::Mul => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .mul(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                interp.conditions().top(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    // Bytecode::Div => interp.binary_op(cs, r1cs::div),
                    // Bytecode::Mod => interp.binary_op(cs, r1cs::mod_),
                    Bytecode::Ret => return Ok(ExitStatus::Return),
                    Bytecode::Call(index) => return Ok(ExitStatus::Call(*index)),
                    Bytecode::CopyLoc(v) => interp.stack.push(self.locals.copy(*v as usize)?),
                    Bytecode::StLoc(v) => self.locals.store(*v as usize, interp.stack.pop()?),
                    Bytecode::MoveLoc(v) => interp.stack.push(self.locals.move_(*v as usize)?),
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        load_constant!(constant, MoveValueType::Bool)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        load_constant!(constant, MoveValueType::Bool)
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
                    Bytecode::Eq => {
                        let a = interp.stack.pop()?;
                        let b = interp.stack.pop()?;
                        let c = evaluation_chip
                            .eq(
                                layouter.namespace(|| format!("eq op in step#{}", interp.step)),
                                a,
                                b,
                                interp.conditions().top(),
                            )
                            .map_err(|e| {
                                error!("eq op failed: {:?}", e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    // Bytecode::Neq => interp.binary_op(cs, r1cs::neq),
                    // Bytecode::And => interp.binary_op(cs, r1cs::and),
                    // Bytecode::Or => interp.binary_op(cs, r1cs::or),
                    // Bytecode::Not => interp.unary_op(cs, r1cs::not),
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
