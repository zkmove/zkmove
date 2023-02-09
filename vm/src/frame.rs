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
use movelang::value::{
    Container, FrameIndex, Index, IntegerType, Reference, Struct, Value, ValueAddress,
};
use std::convert::TryFrom;
use std::ops::{Add, Div, Mul, Not, Rem, Sub};
use std::sync::Arc;
use vm_circuit::witness::arith_operations::ArithOperation;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::rw_operations::{GlobalOp, LocalsOp, RWOperation, RW};

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
        arith_operations: &mut Vec<ArithOperation>,
    ) -> VmResult<ExitStatus<F>> {
        let code = self.function.code();
        let frame_index = interp.frames.size();
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
                    frame_index,
                    locals_index: 0, // will be filled in CopyLoc, StLoc, MoveLoc
                    gc: rw_operations.len(),
                    module_index,
                    function_index,
                    auxiliary_1: None,
                    auxiliary_2: None,
                    auxiliary_3: None,
                    auxiliary_4: None,
                };

                match instruction {
                    Bytecode::LdU8(v) => {
                        let constant = F::from_u128(*v as u128);
                        let value = Value::new(constant, MoveValueType::U8)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u128(*v as u128);
                        let value = Value::new(constant, MoveValueType::U64)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        let value = Value::new(constant, MoveValueType::U128)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::Pop => {
                        let value = interp.stack.pop(rw_operations)?;
                        let flattened_field_count = value.flattened_field_count()?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        Ok(())
                    }
                    Bytecode::Add => {
                        let ty = interp.binary_op(Value::add, rw_operations)?;
                        let num_of_bytes = IntegerType::try_from(ty)?.num_of_bytes();
                        arith_operations.push(ArithOperation {
                            module_index,
                            function_index,
                            pc: self.pc,
                            num_of_bytes,
                        });
                        Ok(())
                    }
                    Bytecode::Sub => {
                        let ty = interp.binary_op(Value::sub, rw_operations)?;
                        let num_of_bytes = IntegerType::try_from(ty)?.num_of_bytes();
                        arith_operations.push(ArithOperation {
                            module_index,
                            function_index,
                            pc: self.pc,
                            num_of_bytes,
                        });
                        Ok(())
                    }
                    Bytecode::Mul => {
                        let ty = interp.binary_op(Value::mul, rw_operations)?;
                        let num_of_bytes = IntegerType::try_from(ty)?.num_of_bytes();
                        arith_operations.push(ArithOperation {
                            module_index,
                            function_index,
                            pc: self.pc,
                            num_of_bytes,
                        });
                        Ok(())
                    }
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
                        interp.step += 1;
                        return Ok(ExitStatus::Return);
                    }
                    Bytecode::Call(index) => {
                        return Ok(ExitStatus::Call(*index, execution_step));
                    }
                    Bytecode::CopyLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = self.locals.copy(*v as usize, frame_index, rw_operations)?;
                        let flattened_field_count = value.flattened_field_count()?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::StLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = interp.stack.pop(rw_operations)?;
                        let flattened_field_count = value.flattened_field_count()?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        self.locals
                            .store(*v as usize, value, frame_index, rw_operations)
                    }
                    Bytecode::MoveLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = self.locals.move_(*v as usize, frame_index, rw_operations)?;
                        let flattened_field_count = value.flattened_field_count()?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::MutBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value =
                            self.locals
                                .mut_borrow(*v as usize, frame_index, rw_operations)?;
                        let flattened_field_count =
                            self.locals.flattened_field_count(*v as usize)?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::ImmBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value =
                            self.locals
                                .imm_borrow(*v as usize, frame_index, rw_operations)?;
                        let flattened_field_count =
                            self.locals.flattened_field_count(*v as usize)?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::ReadRef => {
                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let value = reference.read_ref()?;

                        if !reference.is_global() {
                            let value = value.clone();
                            let container_frame_index = reference.container_frame_index();
                            let index = reference.index();
                            execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                            execution_step.auxiliary_2 =
                                Some(Value::u64(container_frame_index as u64));

                            let flattened_field_count = value.flattened_field_count()?;
                            execution_step.auxiliary_3 =
                                Some(Value::u64(flattened_field_count as u64));

                            let flattened = match reference.clone() {
                                Reference::ContainerRef(_) => {
                                    execution_step.locals_index = index;
                                    value.flatten(ValueAddress::Locals(
                                        FrameIndex(container_frame_index),
                                        Index(index),
                                    ))?
                                }
                                Reference::IndexedRef(r) => {
                                    match r.container() {
                                        Container::Locals(_, _) => {
                                            execution_step.locals_index = index;
                                            value.flatten(ValueAddress::Locals(
                                                FrameIndex(container_frame_index),
                                                Index(index),
                                            ))?
                                        }
                                        // if we come here, the value should be a member of a struct
                                        // we should replace the step's locals_index with the index
                                        // of the struct
                                        Container::Struct(_, _) => {
                                            execution_step.locals_index = r.container().index();
                                            value.flatten(ValueAddress::Member {
                                                index: Index(index),
                                                parent: Box::new(ValueAddress::Locals(
                                                    FrameIndex(container_frame_index),
                                                    Index(r.container().index()),
                                                )),
                                            })?
                                        }
                                    }
                                }
                            };

                            Locals::emit_locals_ops_for_flattened_value(
                                flattened,
                                RW::READ,
                                rw_operations,
                            );
                        } else {
                            execution_step.auxiliary_1 = Some(Value::bool(true)); // is global
                            let (addr, sd_idx) = reference.global_path();
                            let global_value = reference.copy_global_value()?;
                            execution_step.auxiliary_2 = Some(Value::address(addr));
                            // todo: auxiliary_3 is occupied by flattened_field_count
                            execution_step.auxiliary_4 = Some(Value::u128(sd_idx.0 as u128));
                            let global_op = GlobalOp {
                                address: addr,
                                sd_index: sd_idx.0 as usize,
                                nested_address_0: 0,
                                nested_address_1: 0,
                                value: global_value,
                                rw: RW::READ,
                                gc: rw_operations.len(),
                            };
                            rw_operations.push(RWOperation::GlobalOp(global_op));
                        }
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::WriteRef => {
                        let mut reference = interp.stack.pop_as_reference(rw_operations)?;
                        let value = interp.stack.pop(rw_operations)?;
                        let value_copy = value.clone();
                        reference.write_ref(value)?; // must write ref first, then record local_op

                        if !reference.is_global() {
                            let container_frame_index = reference.container_frame_index();
                            let index = reference.index();
                            execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                            execution_step.auxiliary_2 =
                                Some(Value::u64(container_frame_index as u64));

                            let flattened_field_count = value_copy.flattened_field_count()?;
                            execution_step.auxiliary_3 =
                                Some(Value::u64(flattened_field_count as u64));

                            let flattened = match reference.clone() {
                                Reference::ContainerRef(_) => {
                                    execution_step.locals_index = index;
                                    let val = value_copy.update_address(ValueAddress::Locals(
                                        FrameIndex(container_frame_index),
                                        Index(index),
                                    ));
                                    val.flatten(ValueAddress::Locals(
                                        FrameIndex(container_frame_index),
                                        Index(index),
                                    ))?
                                }
                                Reference::IndexedRef(r) => {
                                    match r.container() {
                                        Container::Locals(_, _) => {
                                            execution_step.locals_index = index;
                                            value_copy.flatten(ValueAddress::Locals(
                                                FrameIndex(container_frame_index),
                                                Index(index),
                                            ))?
                                        }
                                        // if we come here, the value should be a member of a struct
                                        // we should replace the step's locals_index with the index
                                        // of the struct
                                        Container::Struct(_, _) => {
                                            execution_step.locals_index = r.container().index();
                                            value_copy.flatten(ValueAddress::Member {
                                                index: Index(index),
                                                parent: Box::new(ValueAddress::Locals(
                                                    FrameIndex(container_frame_index),
                                                    Index(r.container().index()),
                                                )),
                                            })?
                                        }
                                    }
                                }
                            };

                            Locals::emit_locals_ops_for_flattened_value(
                                flattened,
                                RW::WRITE,
                                rw_operations,
                            );
                        } else {
                            execution_step.auxiliary_1 = Some(Value::bool(true)); // is global
                            let (addr, sd_idx) = reference.global_path();
                            let global_value = reference.copy_global_value()?;
                            execution_step.auxiliary_2 = Some(Value::address(addr));
                            // todo: how to ensure auxiliary_3 is exclusive to flattened_field_count?
                            // Allocate a cell 'field_count' specifically for it?
                            execution_step.auxiliary_4 = Some(Value::u128(sd_idx.0 as u128));
                            let global_op = GlobalOp {
                                address: addr,
                                sd_index: sd_idx.0 as usize,
                                nested_address_0: 0,
                                nested_address_1: 0,
                                value: global_value,
                                rw: RW::WRITE,
                                gc: rw_operations.len(),
                            };
                            rw_operations.push(RWOperation::GlobalOp(global_op));
                        }
                        Ok(())
                    }
                    Bytecode::FreezeRef => {
                        // In native Move VM, FreezeRef is just be a null op. There is no difference
                        // between mut and imm ref at runtime. let's follow native Move VM at the moment.
                        // but this can be a security risk in zkMove VM. Need further discussion.
                        Ok(())
                    }
                    Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
                        execution_step.auxiliary_1 = Some(Value::u64(fh_idx.0 as u64));
                        let reference = interp.stack.pop_as_struct_ref(rw_operations)?;
                        let field_offset = resolver.field_offset(*fh_idx);
                        let field_ref = reference.borrow_element(field_offset)?;
                        interp.stack.push(field_ref, rw_operations)
                    }
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        let value = Value::new(constant, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        let value = Value::new(constant, MoveValueType::Bool)?;
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::BrTrue(offset) => {
                        execution_step.auxiliary_1 = Some(Value::u64(*offset as u64));
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
                        execution_step.auxiliary_1 = Some(Value::u64(*offset as u64));
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
                        execution_step.auxiliary_1 = Some(Value::u64(*offset as u64));
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
                    Bytecode::BitAnd => {
                        interp.binary_op(Value::bit_and, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::BitOr => {
                        interp.binary_op(Value::bit_or, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Xor => {
                        interp.binary_op(Value::xor, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Shl => {
                        interp.binary_op(Value::shl_checked, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Shr => {
                        // auxiliary is the reminder = a % (2^b)
                        interp.binary_op(Value::shr_checked, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::And => {
                        interp.binary_op(Value::and, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Or => {
                        interp.binary_op(Value::or, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Not => interp.unary_op(Value::not, rw_operations),
                    Bytecode::CastU8 => interp.unary_op(Value::castu8, rw_operations),
                    Bytecode::CastU64 => interp.unary_op(Value::castu64, rw_operations),
                    Bytecode::CastU128 => interp.unary_op(Value::castu128, rw_operations),
                    Bytecode::Pack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sd_idx.0 as u64));
                        let args = interp.stack.popn(field_count, rw_operations)?;
                        let value = Value::struct_(
                            Struct::pack(args),
                            ValueAddress::Stack(Index(interp.stack.size())),
                        );
                        let flattened_field_count = value.flattened_field_count()?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::Unpack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sd_idx.0 as u64));
                        let (struct_, flattened_field_count) =
                            interp.stack.pop_as_struct(rw_operations)?;
                        execution_step.auxiliary_3 = Some(Value::u64(flattened_field_count as u64));
                        for value in struct_.unpack()? {
                            interp.stack.push(value, rw_operations)?;
                        }
                        Ok(())
                    }
                    Bytecode::Exists(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let exists = interp.exists(data_store, loader, addr, &ty)?;
                        interp.stack.push(Value::bool(exists), rw_operations)
                    }
                    Bytecode::MoveFrom(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let value = interp.move_from(data_store, loader, addr, &ty)?;

                        let global_op = GlobalOp {
                            address: addr,
                            sd_index: sd_idx.0 as usize,
                            nested_address_0: 0,
                            nested_address_1: 0,
                            value: value.clone(),
                            rw: RW::READ,
                            gc: rw_operations.len(),
                        };
                        rw_operations.push(RWOperation::GlobalOp(global_op));

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

                        let global_op = GlobalOp {
                            address: addr,
                            sd_index: sd_idx.0 as usize,
                            nested_address_0: 0,
                            nested_address_1: 0,
                            value: resource.clone(),
                            rw: RW::WRITE,
                            gc: rw_operations.len(),
                        };
                        rw_operations.push(RWOperation::GlobalOp(global_op));

                        interp.move_to(data_store, loader, addr, &ty, resource)
                    }
                    Bytecode::ImmBorrowGlobal(sd_idx) | Bytecode::MutBorrowGlobal(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let value = interp.borrow_global(data_store, loader, addr, &ty, *sd_idx)?;

                        let global_value =
                            value.copy_value().as_reference()?.copy_global_value()?;
                        let global_op = GlobalOp {
                            address: addr,
                            sd_index: sd_idx.0 as usize,
                            nested_address_0: 0,
                            nested_address_1: 0,
                            value: global_value,
                            rw: RW::READ,
                            gc: rw_operations.len(),
                        };
                        rw_operations.push(RWOperation::GlobalOp(global_op));

                        interp.stack.push(value, rw_operations)
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
