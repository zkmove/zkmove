// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use crate::locals::Locals;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::utility::MoveValueType;
use movelang::value::{Container, Reference, Struct, Value};
use std::ops::{Add, Div, Mul, Not, Rem, Sub};
use std::sync::Arc;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::rw_operations::{LocalsOp, RWOperation, RW};

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

    pub fn pc(&self) -> u16 {
        self.pc
    }

    pub fn module_index(&self, data_store: &StateStore<F>) -> Option<u16> {
        match self.function.module_id() {
            Some(module_id) => data_store.module_index(module_id),
            None => Some(0), // function is in the script
        }
    }

    pub fn execute(
        &mut self,
        interp: &mut Interpreter<F>,
        loader: &MoveLoader,
        data_store: &mut StateStore<F>,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
    ) -> VmResult<ExitStatus<F>> {
        let code = self.function.code();
        let call_index = interp.frames.size();
        let module_index = self
            .module_index(data_store)
            .ok_or_else(|| RuntimeError::new(StatusCode::ModuleNotFound))?;
        let function_index = self.function.index().0;
        let resolver = self.function.get_resolver(loader.inner());
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
                        let value = Value::new_variable(Some(constant), None, MoveValueType::U8)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u128(*v as u128);
                        let value = Value::new_variable(Some(constant), None, MoveValueType::U64)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        let value = Value::new_variable(Some(constant), None, MoveValueType::U128)?;
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
                        trace!("step #{}, {:?}", interp.step, execution_step);
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
                    Bytecode::MutBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        interp.stack.push(
                            self.locals
                                .mut_borrow(*v as usize, call_index, rw_operations)?,
                            rw_operations,
                        )
                    }
                    Bytecode::ImmBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        interp.stack.push(
                            self.locals
                                .imm_borrow(*v as usize, call_index, rw_operations)?,
                            rw_operations,
                        )
                    }
                    Bytecode::ReadRef => {
                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let ref_call_index = reference.call_index();
                        let index = reference.index();
                        let value = reference.read_ref()?;
                        execution_step.locals_index = index;
                        execution_step.auxiliary = Some(Value::u64(ref_call_index as u64, None)?);

                        let (locals_value, locals_index) = match reference.clone() {
                            Reference::ContainerRef(_) => (value.clone(), index),
                            Reference::IndexedRef(r) => {
                                match r.container() {
                                    Container::Locals(_) => (value.clone(), index),
                                    // if we come here, the value should be a member of a struct
                                    // we should return the struct instead of the member
                                    Container::Struct(_) => {
                                        (Value::Container(r.container().copy_value()?), r.index())
                                    }
                                }
                            }
                        };
                        let locals_op = LocalsOp {
                            call_index: ref_call_index,
                            index: locals_index,
                            value: locals_value,
                            rw: RW::READ,
                            gc: rw_operations.len(),
                        };
                        rw_operations.push(RWOperation::LocalsOp(locals_op));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::WriteRef => {
                        let mut reference = interp.stack.pop_as_reference(rw_operations)?;
                        let ref_call_index = reference.call_index();
                        let index = reference.index();
                        let value = interp.stack.pop(rw_operations)?;
                        execution_step.locals_index = index;
                        execution_step.auxiliary = Some(Value::u64(ref_call_index as u64, None)?);
                        let value_copy = value.clone();
                        reference.write_ref(value)?; // must write ref first, then record local_op

                        let (locals_value, locals_index) = match reference.clone() {
                            Reference::ContainerRef(_) => (value_copy, index),
                            Reference::IndexedRef(r) => {
                                match r.container() {
                                    Container::Locals(_) => (value_copy, index),
                                    // if we come here, the value should be a member of a struct
                                    // we should return the struct instead of the member
                                    Container::Struct(_) => {
                                        (Value::Container(r.container().copy_value()?), r.index())
                                    }
                                }
                            }
                        };

                        let locals_op = LocalsOp {
                            call_index: ref_call_index,
                            index: locals_index,
                            value: locals_value,
                            rw: RW::WRITE,
                            gc: rw_operations.len(),
                        };
                        rw_operations.push(RWOperation::LocalsOp(locals_op));
                        Ok(())
                    }
                    Bytecode::FreezeRef => {
                        // In native Move VM, FreezeRef is just be a null op. There is no difference
                        // between mut and imm ref at runtime. let's follow native Move VM at the moment.
                        // but this can be a security risk in zkMove VM. Need further discussion.
                        Ok(())
                    }
                    Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
                        execution_step.auxiliary = Some(Value::u64(fh_idx.0 as u64, None)?);
                        let reference = interp.stack.pop_as_struct_ref(rw_operations)?;
                        let field_offset = resolver.field_offset(*fh_idx);
                        let field_ref = reference.borrow_element(field_offset)?;
                        interp.stack.push(field_ref, rw_operations)
                    }
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        let value = Value::new_variable(Some(constant), None, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        let value = Value::new_variable(Some(constant), None, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::BrTrue(offset) => {
                        execution_step.auxiliary = Some(Value::u64(*offset as u64, None)?);
                        let cond =
                            interp.stack.pop(rw_operations)?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        if cond == F::one() {
                            trace!("step #{}, {:?}", interp.step, execution_step);
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
                            trace!("step #{}, {:?}", interp.step, execution_step);
                            exec_steps.push(execution_step);
                            interp.step += 1;
                            self.pc = *offset;
                            break;
                        }
                        Ok(())
                    }
                    Bytecode::Branch(offset) => {
                        execution_step.auxiliary = Some(Value::u64(*offset as u64, None)?);
                        trace!("step #{}, {:?}", interp.step, execution_step);
                        exec_steps.push(execution_step);
                        interp.step += 1;
                        self.pc = *offset;
                        break;
                    }
                    Bytecode::Abort => {
                        trace!("step #{}, {:?}", interp.step, execution_step);
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
                    Bytecode::Le => interp.binary_op_auxiliary(
                        Value::le,
                        Value::diff,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Lt => interp.binary_op_auxiliary(
                        Value::lt,
                        Value::diff,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Ge => interp.binary_op_auxiliary(
                        Value::ge,
                        Value::diff,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::Gt => interp.binary_op_auxiliary(
                        Value::gt,
                        Value::diff,
                        rw_operations,
                        &mut execution_step,
                    ),
                    Bytecode::And => interp.binary_op(Value::and, rw_operations),
                    Bytecode::Or => interp.binary_op(Value::or, rw_operations),
                    Bytecode::Not => interp.unary_op(Value::not, rw_operations),
                    Bytecode::Pack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary = Some(Value::u64(field_count as u64, None)?);
                        let args = interp.stack.popn(field_count, rw_operations)?;
                        interp
                            .stack
                            .push(Value::struct_(Struct::pack(args)), rw_operations)
                    }
                    Bytecode::Unpack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary = Some(Value::u64(field_count as u64, None)?);
                        let struct_ = interp.stack.pop_as_struct(rw_operations)?;
                        for value in struct_.unpack()? {
                            interp.stack.push(value, rw_operations)?;
                        }
                        Ok(())
                    }
                    Bytecode::Exists(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let exists = interp.exists(data_store, loader, addr, &ty)?;
                        interp.stack.push(Value::bool(exists, None)?, rw_operations)
                    }
                    Bytecode::MoveFrom(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let value = interp.move_from(data_store, loader, addr, &ty)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::MoveTo(sd_idx) => {
                        let resource = interp.stack.pop(rw_operations)?;
                        let signer_reference = interp.stack.pop_as_struct_ref(rw_operations)?;
                        let addr = signer_reference
                            .borrow_element(0)?
                            .as_reference()?
                            .read_ref()?
                            .as_account_address()
                            .expect("address should not be None");
                        let ty = resolver.get_struct_type(*sd_idx);
                        interp.move_to(data_store, loader, addr, &ty, resource)
                    }
                    _ => unreachable!(),
                }?;

                trace!("step #{}, {:?}", interp.step, execution_step);
                exec_steps.push(execution_step);
                interp.step += 1;
                self.pc += 1;
            }
        }
    }

    pub fn print_frame(&self) {
        // currently only print bytecode of entry function
        trace!("Bytecode of function {:?}:", self.function.name());
        for (i, instruction) in self.function.code().iter().enumerate() {
            trace!("#{}, {:?}", i, instruction);
        }
    }
}

pub enum ExitStatus<F: FieldExt> {
    Return,
    Call(FunctionHandleIndex, ExecutionStep<F>),
}
