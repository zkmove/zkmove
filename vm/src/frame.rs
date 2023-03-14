// Copyright (c) zkMove Authors

use crate::globals;
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
    ContainerRef, GlobalRef, IndexedLocation, IndexedRef, IntegerType, LocalRef, LocatedValue,
    Reference, Value, ValueLocation,
};
use std::convert::TryFrom;
use std::ops::{Add, Div, Mul, Not, Rem, Sub};
use std::sync::Arc;
use vm_circuit::witness::arith_operations::ArithOperation;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::rw_operations::{RWOperation, RW};

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
                        let word_element_count = value.word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
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
                        let word_element_count = value.word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::StLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = interp.stack.pop(rw_operations)?;
                        let word_element_count = value.word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        self.locals
                            .store(*v as usize, value, frame_index, rw_operations)
                    }
                    Bytecode::MoveLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = self.locals.move_(*v as usize, frame_index, rw_operations)?;
                        let word_element_count = value.word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::ImmBorrowLoc(v) | Bytecode::MutBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let local_ref =
                            self.locals
                                .borrow_locals(*v as usize, frame_index, rw_operations)?;
                        let word_element_count = local_ref.refer.borrow().word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(local_ref.into(), rw_operations)
                    }

                    Bytecode::ReadRef => {
                        // | instr | u8/bool/address | container |
                        // | --- | --- | --- |
                        // | borrow_loc | IndexedRef(idx, ContainerRef::Local(Container::Locals)) | ContainerRef::Local(Container::Struct) |
                        // | borrow_global | unreachable! | ContainerRef::Global(Container::Struct) |
                        // | borrow_field (of ContainerRef::Local) | IndexedRef(idx,[Outer]ContainerRef::Local)  | ContainerRef::Local([Inner]Container::Struct) |
                        // | borrow_field (of ContainerRef::Global) | IndexedRef(idx,[Outer]ContainerRef::Global)  | ContainerRef::Global([Inner]Container::Struct)  |

                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let value = reference.read_ref()?;
                        match reference {
                            Reference::GlobalRef(GlobalRef { loc, .. }) => {
                                let (account_addr, sd_index) = (loc.address, loc.sd_index);
                                let word =
                                    LocatedValue(ValueLocation::Global(loc), &value).flatten();
                                let word_element_count = word.len();
                                execution_step.auxiliary_1 = Some(Value::bool(true)); // global
                                execution_step.auxiliary_2 = Some(Value::Address(account_addr));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64)); // word_elem_count
                                execution_step.auxiliary_4 = Some(Value::u128(sd_index.0 as u128));
                                globals::emit_global_ops_for_word(
                                    word,
                                    account_addr,
                                    sd_index,
                                    RW::READ,
                                    rw_operations,
                                );
                            }
                            Reference::LocalRef(LocalRef { loc, .. }) => {
                                let frame_index = loc.frame_index;
                                let index = loc.index;
                                let word =
                                    LocatedValue(ValueLocation::Local(loc), &value).flatten();
                                let word_element_count = word.len();
                                execution_step.locals_index = index as usize;
                                execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                                execution_step.auxiliary_2 = Some(Value::u64(frame_index.0 as u64));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64)); // word_elem_count
                                Locals::emit_locals_ops_for_word(word, RW::READ, rw_operations);
                            }
                            Reference::IndexedRef(IndexedRef {
                                sub_indexes,
                                container_ref,
                            }) => {
                                match container_ref {
                                    ContainerRef::Global(vloc, _) => {
                                        let (account_addr, sd_index) =
                                            (vloc.address, vloc.sd_index);
                                        let indexed_value = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Global(vloc),
                                            },
                                            &value,
                                        );
                                        let word = indexed_value.flatten();
                                        let word_element_count = word.len();
                                        execution_step.auxiliary_1 = Some(Value::bool(true)); // global
                                        execution_step.auxiliary_2 =
                                            Some(Value::Address(account_addr));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64)); // word_elem_count
                                        execution_step.auxiliary_4 =
                                            Some(Value::u128(sd_index.0 as u128));
                                        globals::emit_global_ops_for_word(
                                            word,
                                            account_addr,
                                            sd_index,
                                            RW::READ,
                                            rw_operations,
                                        );
                                    }
                                    ContainerRef::Local(vloc, _) => {
                                        let frame_index = vloc.frame_index;
                                        let index = vloc.index;
                                        let indexed_value = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Local(vloc),
                                            },
                                            &value,
                                        );
                                        let word = indexed_value.flatten();
                                        let word_element_count = word.len();
                                        execution_step.locals_index = index as usize;
                                        execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                                        execution_step.auxiliary_2 =
                                            Some(Value::u64(frame_index.0 as u64));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64)); // word_elem_count
                                        Locals::emit_locals_ops_for_word(
                                            word,
                                            RW::READ,
                                            rw_operations,
                                        );
                                    }
                                }
                            }
                        }
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::WriteRef => {
                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let value = interp.stack.pop(rw_operations)?;
                        reference.write_ref(value)?; // must write ref first, then record local_op
                        let value = reference.read_ref()?; // read back, it's a deep copy of origin value
                                                           //let value_address = reference.value_address();

                        match reference {
                            Reference::LocalRef(LocalRef { loc, .. }) => {
                                let word =
                                    LocatedValue(ValueLocation::Local(loc), &value).flatten();
                                let word_element_count = value.word_element_count();
                                execution_step.locals_index = loc.index as usize;
                                execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                                execution_step.auxiliary_2 =
                                    Some(Value::u64(loc.frame_index.0 as u64));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64));
                                Locals::emit_locals_ops_for_word(word, RW::WRITE, rw_operations);
                            }
                            Reference::GlobalRef(GlobalRef { loc, .. }) => {
                                let (account_addr, sd_idx) = (loc.address, loc.sd_index);
                                let word =
                                    LocatedValue(ValueLocation::Global(loc), &value).flatten();

                                execution_step.auxiliary_1 = Some(Value::bool(true)); // is global
                                execution_step.auxiliary_2 = Some(Value::address(account_addr));
                                execution_step.auxiliary_3 = Some(Value::u64(word.len() as u64)); // word_elem_count
                                execution_step.auxiliary_4 = Some(Value::u128(sd_idx.0 as u128));
                                globals::emit_global_ops_for_word(
                                    word.clone(),
                                    account_addr,
                                    sd_idx,
                                    RW::WRITE,
                                    rw_operations,
                                );
                            }
                            Reference::IndexedRef(IndexedRef {
                                sub_indexes,
                                container_ref,
                            }) => {
                                match container_ref {
                                    ContainerRef::Local(vloc, _) => {
                                        let word = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Local(vloc),
                                            },
                                            &value,
                                        )
                                        .flatten();
                                        let word_element_count = value.word_element_count();
                                        execution_step.locals_index = vloc.index as usize;
                                        execution_step.auxiliary_1 = Some(Value::bool(false)); // is not global
                                        execution_step.auxiliary_2 =
                                            Some(Value::u64(vloc.frame_index.0 as u64));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64));
                                        Locals::emit_locals_ops_for_word(
                                            word,
                                            RW::WRITE,
                                            rw_operations,
                                        );
                                    }
                                    ContainerRef::Global(vloc, _) => {
                                        let (account_addr, sd_idx) = (vloc.address, vloc.sd_index);
                                        let word = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Global(vloc),
                                            },
                                            &value,
                                        )
                                        .flatten();

                                        execution_step.auxiliary_1 = Some(Value::bool(true)); // is global
                                        execution_step.auxiliary_2 =
                                            Some(Value::address(account_addr));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word.len() as u64)); // word_elem_count
                                        execution_step.auxiliary_4 =
                                            Some(Value::u128(sd_idx.0 as u128));
                                        globals::emit_global_ops_for_word(
                                            word.clone(),
                                            account_addr,
                                            sd_idx,
                                            RW::WRITE,
                                            rw_operations,
                                        );
                                    }
                                }
                            }
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
                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let word_element_count = reference.value_address_path().len();
                        let field_offset = resolver.field_offset(*fh_idx);
                        let field_ref = reference.try_borrow_field(field_offset as u128)?;
                        execution_step.auxiliary_1 = Some(Value::u64(fh_idx.0 as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(field_offset as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(field_ref.into(), rw_operations)
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
                        let value = Value::struct_(args);
                        let word_element_count = value.word_element_count();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::Unpack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sd_idx.0 as u64));
                        let (struct_, word_element_count) =
                            interp.stack.pop_as_struct(rw_operations)?;
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
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
                        // in fact, after move_from, user cannot call move_from again, as the struct is already gone.
                        // If this limit is constrained by bytecode verifier, then circuit doesn't need to worry about this.
                        // But if not, we should write a Invalid to the global struct.
                        // For now, we take a progressive action.
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            *sd_idx,
                            value.clone(),
                            RW::READ,
                            true,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::MoveTo(sd_idx) => {
                        let resource = interp.stack.pop(rw_operations)?;
                        let signer_reference = interp.stack.pop_as_reference(rw_operations)?;
                        let addr_value =
                            Reference::IndexedRef(signer_reference.try_borrow_field(0)?)
                                .read_ref()?;

                        let addr = addr_value
                            .into_account_address()
                            .expect("address should not be None");
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            *sd_idx,
                            resource.clone(),
                            RW::WRITE,
                            false,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));

                        let ty = resolver.get_struct_type(*sd_idx);
                        interp.move_to(data_store, loader, addr, &ty, resource)
                    }
                    Bytecode::ImmBorrowGlobal(sd_idx) | Bytecode::MutBorrowGlobal(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let global_ref = Reference::GlobalRef(
                            interp.borrow_global(data_store, loader, addr, &ty, *sd_idx)?,
                        );
                        let global_value = global_ref.read_ref()?;
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            *sd_idx,
                            global_value,
                            RW::READ,
                            false,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));

                        interp.stack.push(global_ref.into(), rw_operations)
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
