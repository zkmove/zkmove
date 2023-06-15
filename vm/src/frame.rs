// Copyright (c) zkMove Authors

use crate::globals;
use crate::interpreter::Interpreter;
use crate::locals;
use crate::locals::Locals;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex, FunctionInstantiationIndex};
use move_vm_runtime::loader::Function;
use movelang::generic_call_graph::{Edge, GenericCallGraph, Node, NodeIndex, NodeInternal};
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use movelang::utility::MoveValueType;
use movelang::value::{
    ContainerRef, GlobalRef, IndexedLocation, IndexedRef, LocalRef, LocatedValue, Location,
    PrimitiveValue, Reference, Value, ValueLocation,
};
use movelang::word::{LocatedWord, Word};
use petgraph::prelude::EdgeRef;
use petgraph::Direction;
use std::convert::From;
use std::ops::{Add, Deref, Div, Mul, Not, Rem, Sub};
use std::sync::Arc;
use vm_circuit::witness::call_trace_table::pos_to_id;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::input_type_elements::GenericTypeMaterialization;
use vm_circuit::witness::rw_operations::{RWOperation, RW};

pub struct Frame<F: FieldExt> {
    generic_node_index: NodeIndex,
    generic_node: Node,
    pc: u16,
    locals: Locals<F>,
    function: Arc<Function>,
    #[allow(dead_code)]
    ty_args: Vec<MoveValueType>,
}

impl<F: FieldExt> Frame<F> {
    pub fn new(
        generic_node_index: NodeIndex,
        generic_node: Node,
        function: Arc<Function>,
        type_arguments: Vec<MoveValueType>,
        locals: Locals<F>,
    ) -> Self {
        Frame {
            generic_node_index,
            generic_node,
            pc: 0,
            locals,
            function,
            ty_args: type_arguments,
        }
    }
    pub fn generic_index(&self) -> NodeIndex {
        self.generic_node_index
    }

    pub fn ty_args(&self) -> &[MoveValueType] {
        &self.ty_args
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
    pub(crate) fn get_next_call_node(&self, graph: &GenericCallGraph, internal: bool) -> NodeIndex {
        let edge_to_follow = if !internal {
            Edge::External {
                pc: self.pc() as usize,
            }
        } else {
            Edge::Internal {
                pc: self.pc() as usize,
            }
        };

        let mut nexts: Vec<_> = graph
            .graph
            .edges_directed(self.generic_index(), Direction::Outgoing)
            .filter(|edge| {
                let e = edge.weight();
                e == &edge_to_follow
            })
            .map(|edge| edge.target())
            .collect();
        assert_eq!(nexts.len(), 1);
        trace!(
            "frame: {:?} -> {:?}",
            self.generic_index(),
            nexts.last().unwrap()
        );
        nexts.pop().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &mut self,
        interp: &mut Interpreter<F>,
        call_graph: &GenericCallGraph,
        loader: &MoveLoader,
        data_store: &mut StateStore<F>,
        exec_steps: &mut Vec<ExecutionStep<F>>,
        rw_operations: &mut Vec<RWOperation<F>>,
        generic_types: &mut Vec<GenericTypeMaterialization>,
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
                    context_id: pos_to_id(self.generic_node.pos()),
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
                    auxiliary_5: None,
                    data: None,
                };

                match instruction {
                    Bytecode::LdConst(const_index) => {
                        let constant = resolver.constant_at(*const_index);
                        let val: PrimitiveValue<_> = constant
                            .deserialize_constant()
                            .ok_or_else(|| {
                                RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                                    .with_message(
                                    "Verifier failed to verify the deserialization of constants"
                                        .to_owned(),
                                )
                            })?
                            .into();
                        execution_step.auxiliary_1 = Some(Value::u64(const_index.0 as u64));
                        interp.stack.push(val.into(), rw_operations)
                    }
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
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        Ok(())
                    }
                    Bytecode::Add => {
                        interp.binary_op(Value::add, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Sub => {
                        interp.binary_op(Value::sub, rw_operations)?;
                        Ok(())
                    }
                    Bytecode::Mul => {
                        interp.binary_op(Value::mul, rw_operations)?;
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
                    Bytecode::CallGeneric(index) => {
                        return Ok(ExitStatus::CallGeneric(*index, execution_step));
                    }
                    Bytecode::CopyLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = self.locals.copy(*v as usize, frame_index, rw_operations)?;
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::StLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = interp.stack.pop(rw_operations)?;
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        self.locals
                            .store(*v as usize, value, frame_index, rw_operations)
                    }
                    Bytecode::MoveLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let value = self.locals.move_(*v as usize, frame_index, rw_operations)?;
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::ImmBorrowLoc(v) | Bytecode::MutBorrowLoc(v) => {
                        execution_step.locals_index = *v as usize;
                        let local_ref =
                            self.locals
                                .borrow_locals(*v as usize, frame_index, rw_operations)?;
                        let word_element_count =
                            Word::from(local_ref.refer.borrow().deref()).0.len();
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
                                let word: LocatedWord<F> =
                                    LocatedValue(ValueLocation::Global(loc), &value).into();
                                let word_element_count = word.0.len();
                                execution_step.auxiliary_2 = Some(Value::Address(account_addr));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64)); // word_elem_count
                                execution_step.auxiliary_4 = Some(Value::u128(sd_index.to_u128()));
                                execution_step.auxiliary_5 = Some(Value::bool(true)); // global
                                globals::emit_global_ops_for_word(word, RW::READ, rw_operations);
                            }
                            Reference::LocalRef(LocalRef { loc, .. }) => {
                                let frame_index = loc.frame_index;
                                let index = loc.index;
                                let word: LocatedWord<F> =
                                    LocatedValue(ValueLocation::Local(loc), &value).into();
                                let word_element_count = word.0.len();
                                execution_step.locals_index = index as usize;
                                execution_step.auxiliary_2 = Some(Value::u64(frame_index.0 as u64));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64)); // word_elem_count
                                execution_step.auxiliary_5 = Some(Value::bool(false)); // is not global
                                locals::emit_locals_ops_for_word(word, RW::READ, rw_operations);
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
                                        let word: LocatedWord<F> = indexed_value.into();
                                        let word_element_count = word.0.len();
                                        execution_step.auxiliary_2 =
                                            Some(Value::Address(account_addr));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64)); // word_elem_count
                                        execution_step.auxiliary_4 =
                                            Some(Value::u128(sd_index.to_u128()));
                                        execution_step.auxiliary_5 = Some(Value::bool(true)); // global
                                        globals::emit_global_ops_for_word(
                                            word,
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
                                        let word: LocatedWord<F> = indexed_value.into();
                                        let word_element_count = word.0.len();
                                        execution_step.locals_index = index as usize;
                                        execution_step.auxiliary_2 =
                                            Some(Value::u64(frame_index.0 as u64));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64)); // word_elem_count
                                        execution_step.auxiliary_5 = Some(Value::bool(false)); // is not global
                                        locals::emit_locals_ops_for_word(
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
                                let word: LocatedWord<F> =
                                    LocatedValue(ValueLocation::Local(loc), &value).into();
                                let word_element_count = Word::from(&value).0.len();
                                execution_step.locals_index = loc.index as usize;
                                execution_step.auxiliary_2 =
                                    Some(Value::u64(loc.frame_index.0 as u64));
                                execution_step.auxiliary_3 =
                                    Some(Value::u64(word_element_count as u64));
                                execution_step.auxiliary_5 = Some(Value::bool(false)); // is not global
                                locals::emit_locals_ops_for_word(word, RW::WRITE, rw_operations);
                            }
                            Reference::GlobalRef(GlobalRef { loc, .. }) => {
                                let (account_addr, sd_idx) = (loc.address, loc.sd_index);
                                let word: LocatedWord<F> =
                                    LocatedValue(ValueLocation::Global(loc), &value).into();

                                execution_step.auxiliary_2 = Some(Value::address(account_addr));
                                execution_step.auxiliary_3 = Some(Value::u64(word.0.len() as u64)); // word_elem_count
                                execution_step.auxiliary_4 = Some(Value::u128(sd_idx.to_u128()));
                                execution_step.auxiliary_5 = Some(Value::bool(true)); // is global
                                globals::emit_global_ops_for_word(
                                    word.clone(),
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
                                        let word: LocatedWord<F> = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Local(vloc),
                                            },
                                            &value,
                                        )
                                        .into();
                                        let word_element_count = Word::from(&value).0.len();
                                        execution_step.locals_index = vloc.index as usize;
                                        execution_step.auxiliary_2 =
                                            Some(Value::u64(vloc.frame_index.0 as u64));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word_element_count as u64));
                                        execution_step.auxiliary_5 = Some(Value::bool(false)); // is not global
                                        locals::emit_locals_ops_for_word(
                                            word,
                                            RW::WRITE,
                                            rw_operations,
                                        );
                                    }
                                    ContainerRef::Global(vloc, _) => {
                                        let (account_addr, sd_idx) = (vloc.address, vloc.sd_index);
                                        let word: LocatedWord<F> = LocatedValue(
                                            IndexedLocation {
                                                sub_indexes,
                                                value_loc: ValueLocation::Global(vloc),
                                            },
                                            &value,
                                        )
                                        .into();

                                        execution_step.auxiliary_2 =
                                            Some(Value::address(account_addr));
                                        execution_step.auxiliary_3 =
                                            Some(Value::u64(word.0.len() as u64)); // word_elem_count
                                        execution_step.auxiliary_4 =
                                            Some(Value::u128(sd_idx.to_u128()));
                                        execution_step.auxiliary_5 = Some(Value::bool(true)); // is global
                                        globals::emit_global_ops_for_word(
                                            word.clone(),
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
                        let field_ref = reference.try_borrow_field(field_offset)?;
                        execution_step.auxiliary_1 = Some(Value::u64(fh_idx.0 as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(field_offset as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(field_ref.into(), rw_operations)
                    }
                    Bytecode::ImmBorrowFieldGeneric(fh_idx)
                    | Bytecode::MutBorrowFieldGeneric(fh_idx) => {
                        let reference = interp.stack.pop_as_reference(rw_operations)?;
                        let word_element_count = reference.value_address_path().len();
                        let field_offset = resolver.field_instantiation_offset(*fh_idx);
                        let field_ref = reference.try_borrow_field(field_offset)?;
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
                        let value = Value::container(args);
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::PackGeneric(sd_idx) => {
                        let field_count = resolver.field_instantiation_count(*sd_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sd_idx.0 as u64));
                        let args = interp.stack.popn(field_count, rw_operations)?;
                        let value = Value::container(args);
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::Unpack(sd_idx) => {
                        let field_count = resolver.field_count(*sd_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sd_idx.0 as u64));
                        let (struct_, word_element_count) =
                            interp.stack.pop_as_container(rw_operations)?;
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        for value in struct_.unpack() {
                            interp.stack.push(value, rw_operations)?;
                        }
                        Ok(())
                    }
                    Bytecode::UnpackGeneric(sdi_idx) => {
                        let field_count = resolver.field_instantiation_count(*sdi_idx);
                        execution_step.auxiliary_1 = Some(Value::u64(field_count as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(sdi_idx.0 as u64));
                        let (struct_, word_element_count) =
                            interp.stack.pop_as_container(rw_operations)?;
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        for value in struct_.unpack() {
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
                    Bytecode::ExistsGeneric(sd_idx) => {
                        let next_node_index = self.get_next_call_node(call_graph, true);
                        let callee_node = call_graph.graph.node_weight(next_node_index).unwrap();
                        let callee_node_data = {
                            if let NodeInternal::StorageOp(call) = callee_node.data() {
                                call
                            } else {
                                unreachable!()
                            }
                        };
                        generic_types.push(GenericTypeMaterialization {
                            execution_step_index: exec_steps.len(),
                            op: instruction.clone(),
                            frame_index: frame_index as u64,
                            instantiation_point_pc: execution_step.pc as u64,
                            instantiation_point_id: pos_to_id(callee_node.pos()),
                            instantiation_point_module: None,
                            instantiation_point_function: instruction.clone().into(),
                            type_args: vec![callee_node_data.struct_type.clone()],
                        });
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_2 =
                            Some(Value::u128(pos_to_id(callee_node.pos())));
                        let caller_pc = interp.frames.top().map(|f| f.pc()).unwrap_or(0);
                        execution_step.auxiliary_4 = Some(Value::u64(caller_pc as u64));

                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.instantiate_generic_type(*sd_idx, self.ty_args()).map_err(|e| {
                            error!("fail to resolver.instantiate_generic_type, index: {}, ty_args: {:?}, error: {:?}", sd_idx, self.ty_args(), e);
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                        })?;

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
                            (*sd_idx).into(),
                            value.clone(),
                            RW::READ,
                            true,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::MoveFromGeneric(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.instantiate_generic_type(*sd_idx, self.ty_args()).map_err(|e| {
                            error!("fail to resolver.instantiate_generic_type, index: {}, ty_args: {:?}, error: {:?}", sd_idx, self.ty_args(), e);
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                        })?;
                        let value = interp.move_from(data_store, loader, addr, &ty)?;
                        // in fact, after move_from, user cannot call move_from again, as the struct is already gone.
                        // If this limit is constrained by bytecode verifier, then circuit doesn't need to worry about this.
                        // But if not, we should write a Invalid to the global struct.
                        // For now, we take a progressive action.
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            (*sd_idx).into(),
                            value.clone(),
                            RW::READ,
                            true,
                            rw_operations,
                        )?;
                        let next_node_index = self.get_next_call_node(call_graph, true);
                        let callee_node = call_graph.graph.node_weight(next_node_index).unwrap();
                        let callee_node_data = {
                            if let NodeInternal::StorageOp(call) = callee_node.data() {
                                call
                            } else {
                                unreachable!()
                            }
                        };
                        generic_types.push(GenericTypeMaterialization {
                            execution_step_index: exec_steps.len(),
                            op: instruction.clone(),
                            frame_index: frame_index as u64,
                            instantiation_point_pc: execution_step.pc as u64,
                            instantiation_point_id: pos_to_id(callee_node.pos()),
                            instantiation_point_module: None,
                            instantiation_point_function: instruction.clone().into(),
                            type_args: vec![callee_node_data.struct_type.clone()],
                        });
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_2 =
                            Some(Value::u128(pos_to_id(callee_node.pos())));
                        let caller_pc = interp.frames.top().map(|f| f.pc()).unwrap_or(0);
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));
                        execution_step.auxiliary_4 = Some(Value::u64(caller_pc as u64));
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
                            (*sd_idx).into(),
                            resource.clone(),
                            RW::WRITE,
                            false,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));

                        let ty = resolver.get_struct_type(*sd_idx);
                        interp.move_to(data_store, loader, addr, &ty, resource)
                    }
                    Bytecode::MoveToGeneric(sd_idx) => {
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
                            (*sd_idx).into(),
                            resource.clone(),
                            RW::WRITE,
                            false,
                            rw_operations,
                        )?;
                        let next_node_index = self.get_next_call_node(call_graph, true);
                        let callee_node = call_graph.graph.node_weight(next_node_index).unwrap();
                        let callee_node_data = {
                            if let NodeInternal::StorageOp(call) = callee_node.data() {
                                call
                            } else {
                                unreachable!()
                            }
                        };
                        generic_types.push(GenericTypeMaterialization {
                            execution_step_index: exec_steps.len(),
                            op: instruction.clone(),
                            frame_index: frame_index as u64,
                            instantiation_point_pc: execution_step.pc as u64,
                            instantiation_point_id: pos_to_id(callee_node.pos()),
                            instantiation_point_module: None,
                            instantiation_point_function: instruction.clone().into(),
                            type_args: vec![callee_node_data.struct_type.clone()],
                        });
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_2 =
                            Some(Value::u128(pos_to_id(callee_node.pos())));
                        let caller_pc = interp.frames.top().map(|f| f.pc()).unwrap_or(0);
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));
                        execution_step.auxiliary_4 = Some(Value::u64(caller_pc as u64));

                        let ty = resolver.instantiate_generic_type(*sd_idx, self.ty_args()).map_err(|e| {
                            error!("fail to resolver.instantiate_generic_type, index: {}, ty_args: {:?}, error: {:?}", sd_idx, self.ty_args(), e);
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                        })?;
                        interp.move_to(data_store, loader, addr, &ty, resource)
                    }
                    Bytecode::ImmBorrowGlobal(sd_idx) | Bytecode::MutBorrowGlobal(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.get_struct_type(*sd_idx);
                        let global_ref = Reference::GlobalRef(interp.borrow_global(
                            data_store,
                            loader,
                            addr,
                            &ty,
                            (*sd_idx).into(),
                        )?);
                        let global_value = global_ref.read_ref()?;
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            (*sd_idx).into(),
                            global_value,
                            RW::READ,
                            false,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));

                        interp.stack.push(global_ref.into(), rw_operations)
                    }
                    Bytecode::ImmBorrowGlobalGeneric(sd_idx)
                    | Bytecode::MutBorrowGlobalGeneric(sd_idx) => {
                        let addr = interp.stack.pop_as_account_address(rw_operations)?;
                        let ty = resolver.instantiate_generic_type(*sd_idx, self.ty_args()).map_err(|e| {
                            error!("fail to resolver.instantiate_generic_type, index: {}, ty_args: {:?}, error: {:?}", sd_idx, self.ty_args(), e);
                            RuntimeError::new(StatusCode::UnknownInvariantViolationError)
                        })?;
                        let global_ref = Reference::GlobalRef(interp.borrow_global(
                            data_store,
                            loader,
                            addr,
                            &ty,
                            (*sd_idx).into(),
                        )?);
                        let global_value = global_ref.read_ref()?;
                        let word_elem_num = globals::emit_ops_for_global_value(
                            addr,
                            (*sd_idx).into(),
                            global_value,
                            RW::READ,
                            false,
                            rw_operations,
                        )?;
                        execution_step.auxiliary_1 = Some(Value::u64(sd_idx.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_elem_num as u64));

                        let next_node_index = self.get_next_call_node(call_graph, true);
                        let callee_node = call_graph.graph.node_weight(next_node_index).unwrap();
                        let callee_node_data = {
                            if let NodeInternal::StorageOp(call) = callee_node.data() {
                                call
                            } else {
                                unreachable!()
                            }
                        };
                        generic_types.push(GenericTypeMaterialization {
                            execution_step_index: exec_steps.len(),
                            op: instruction.clone(),
                            frame_index: frame_index as u64,
                            instantiation_point_pc: execution_step.pc as u64,
                            instantiation_point_id: pos_to_id(callee_node.pos()),
                            instantiation_point_module: None,
                            instantiation_point_function: instruction.clone().into(),
                            type_args: vec![callee_node_data.struct_type.clone()],
                        });
                        execution_step.auxiliary_2 =
                            Some(Value::u128(pos_to_id(callee_node.pos())));
                        let caller_pc = interp.frames.top().map(|f| f.pc()).unwrap_or(0);
                        execution_step.auxiliary_4 = Some(Value::u64(caller_pc as u64));

                        interp.stack.push(global_ref.into(), rw_operations)
                    }
                    Bytecode::VecPack(si, num) => {
                        execution_step.auxiliary_1 = Some(Value::u64(*num as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(si.0 as u64));
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;
                        let elements = interp.stack.popn(*num as u16, rw_operations)?;
                        let value = Value::container(elements);
                        let word_element_count = Word::from(&value).0.len();
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        interp.stack.push(value, rw_operations)
                    }
                    Bytecode::VecLen(si) => {
                        let vec_ref = interp.stack.pop_as_vector_ref(rw_operations)?;
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;

                        // emit read op for vec header
                        let vec = vec_ref.read_ref()?;
                        let word: LocatedWord<F> = match vec_ref.location()? {
                            Location::ValueLocation(l) => LocatedValue(l, &vec).into(),
                            Location::IndexedLocation(l) => LocatedValue(l, &vec).into(),
                        };
                        if vec_ref.is_global() {
                            let (header_address_path, header_value) =
                                word.0.first().expect("header address should not be none");
                            globals::emit_global_op(
                                header_address_path.clone(),
                                *header_value,
                                RW::READ,
                                rw_operations,
                            );
                            execution_step.auxiliary_1 = Some(Value::bool(true));
                        } else {
                            let (header_address_path, header_value) =
                                word.0.first().expect("header address should not be none");
                            locals::emit_locals_op(
                                header_address_path.clone(),
                                *header_value,
                                RW::READ,
                                rw_operations,
                            );
                            execution_step.auxiliary_1 = Some(Value::bool(false));
                        }
                        execution_step.auxiliary_2 = Some(Value::u64(si.0 as u64));

                        let vec_len = vec_ref.length()?;
                        interp.stack.push(Value::u64(vec_len as u64), rw_operations)
                    }
                    Bytecode::VecImmBorrow(si) | Bytecode::VecMutBorrow(si) => {
                        let idx = interp.stack.pop_as_u64(rw_operations)? as usize;
                        let vec_ref = interp.stack.pop_as_vector_ref(rw_operations)?;
                        let word_element_count = vec_ref.value_address_path().len();
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;
                        execution_step.auxiliary_1 = Some(Value::u64(si.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        let res = vec_ref.try_borrow_elem(idx)?;
                        interp.stack.push(res.into(), rw_operations)
                    }
                    Bytecode::VecPushBack(si) => {
                        let value = interp.stack.pop(rw_operations)?;
                        let word_element_count = Word::from(&value).0.len();
                        let vec_ref = interp.stack.pop_as_vector_ref(rw_operations)?;
                        let ref_val_flattened_len = vec_ref.value_address_path().len();
                        let headers = vec_ref.current_and_parent_container_headers()?;
                        debug_assert!(!headers.is_empty());
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;
                        vec_ref.push_back(value)?;

                        // emit rw operations
                        let value_idx = vec_ref.length()? - 1;
                        let value_ref = vec_ref.try_borrow_elem(value_idx)?;
                        let (value_loc, value) =
                            VmResult::<(IndexedLocation<F>, Value<F>)>::from(value_ref)?;
                        let word: LocatedWord<F> = LocatedValue(value_loc, &value).into();
                        let is_global = vec_ref.is_global();
                        if is_global {
                            globals::emit_global_ops_for_word(word, RW::WRITE, rw_operations);
                            execution_step.auxiliary_5 = Some(Value::bool(true));
                        } else {
                            locals::emit_locals_ops_for_word(word, RW::WRITE, rw_operations);
                            execution_step.auxiliary_5 = Some(Value::bool(false));
                        }

                        execution_step.auxiliary_1 = Some(Value::u64(si.0 as u64));
                        // auxiliary_2 is multiplexed by header_len and value_index.
                        let val = (value_idx << 8) + headers.len();
                        execution_step.auxiliary_2 = Some(Value::u64(val as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        execution_step.auxiliary_4 = Some(Value::u64(ref_val_flattened_len as u64));

                        // update container headers
                        for (loc, header_value) in headers {
                            if is_global {
                                globals::emit_global_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::READ,
                                    rw_operations,
                                );
                            } else {
                                locals::emit_locals_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::READ,
                                    rw_operations,
                                );
                            }
                        }
                        let new_headers = vec_ref.current_and_parent_container_headers()?;
                        debug_assert!(!new_headers.is_empty());
                        for (loc, header_value) in new_headers {
                            if is_global {
                                globals::emit_global_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::WRITE,
                                    rw_operations,
                                );
                            } else {
                                locals::emit_locals_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::WRITE,
                                    rw_operations,
                                );
                            }
                        }

                        Ok(())
                    }
                    Bytecode::VecPopBack(si) => {
                        let vec_ref = interp.stack.pop_as_vector_ref(rw_operations)?;
                        let ref_val_flattened_len = vec_ref.value_address_path().len();
                        let headers = vec_ref.current_and_parent_container_headers()?;
                        debug_assert!(!headers.is_empty());
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;

                        // emit rw operations
                        let value_idx = vec_ref.length()? - 1;
                        let value_ref = vec_ref.try_borrow_elem(value_idx)?;
                        let (value_loc, value) =
                            VmResult::<(IndexedLocation<F>, Value<F>)>::from(value_ref)?;
                        let word: LocatedWord<F> = LocatedValue(value_loc, &value).into();
                        let is_global = vec_ref.is_global();
                        if is_global {
                            globals::emit_global_ops_for_word(word, RW::READ, rw_operations);
                            execution_step.auxiliary_5 = Some(Value::bool(true));
                        } else {
                            locals::emit_locals_ops_for_word(word, RW::READ, rw_operations);
                            execution_step.auxiliary_5 = Some(Value::bool(false));
                        }
                        let word_element_count = Word::from(&value).0.len();

                        execution_step.auxiliary_1 = Some(Value::u64(si.0 as u64));
                        // auxiliary_2 is multiplexed by header_len and value_index.
                        let val = (value_idx << 8) + headers.len();
                        execution_step.auxiliary_2 = Some(Value::u64(val as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        execution_step.auxiliary_4 = Some(Value::u64(ref_val_flattened_len as u64));

                        let val = vec_ref.pop()?;
                        interp.stack.push(val, rw_operations)?;

                        // update container headers
                        for (loc, header_value) in headers {
                            if is_global {
                                globals::emit_global_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::READ,
                                    rw_operations,
                                );
                            } else {
                                locals::emit_locals_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::READ,
                                    rw_operations,
                                );
                            }
                        }
                        let new_headers = vec_ref.current_and_parent_container_headers()?;
                        debug_assert!(!new_headers.is_empty());
                        for (loc, header_value) in new_headers {
                            if is_global {
                                globals::emit_global_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::WRITE,
                                    rw_operations,
                                );
                            } else {
                                locals::emit_locals_op(
                                    loc.to_address_path().fill_up(),
                                    header_value,
                                    RW::WRITE,
                                    rw_operations,
                                );
                            }
                        }

                        Ok(())
                    }
                    Bytecode::VecUnpack(si, num) => {
                        let (vec, word_element_count) =
                            interp.stack.pop_as_container(rw_operations)?;
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;
                        let elements = vec.unpack();
                        for value in elements {
                            interp.stack.push(value, rw_operations)?;
                        }

                        execution_step.auxiliary_1 = Some(Value::u64(*num as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(si.0 as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_element_count as u64));
                        Ok(())
                    }
                    Bytecode::VecSwap(si) => {
                        let idx_b = interp.stack.pop_as_u64(rw_operations)? as usize;
                        let idx_a = interp.stack.pop_as_u64(rw_operations)? as usize;
                        let vec_ref = interp.stack.pop_as_vector_ref(rw_operations)?;
                        let ref_val_flattened_len = vec_ref.value_address_path().len();
                        //fixme: need type check?
                        let _ty = resolver
                            .instantiate_single_type(*si, self.ty_args())
                            .map_err(|e| {
                                error!("instantiate type failed: {:?}", e);
                                RuntimeError::new(StatusCode::InstantiateTypeFailed)
                            })?;

                        // emit rw operations
                        let elem_a_ref = vec_ref.try_borrow_elem(idx_a)?;
                        let elem_b_ref = vec_ref.try_borrow_elem(idx_b)?;
                        let (elem_a_loc, elem_a) =
                            VmResult::<(IndexedLocation<F>, Value<F>)>::from(elem_a_ref)?;
                        let (elem_b_loc, elem_b) =
                            VmResult::<(IndexedLocation<F>, Value<F>)>::from(elem_b_ref)?;

                        let is_global = vec_ref.is_global();
                        if is_global {
                            globals::emit_global_ops_for_word(
                                LocatedValue(elem_a_loc.clone(), &elem_a).into(),
                                RW::READ,
                                rw_operations,
                            );
                            globals::emit_global_ops_for_word(
                                LocatedValue(elem_b_loc.clone(), &elem_b).into(),
                                RW::READ,
                                rw_operations,
                            );
                            globals::emit_global_ops_for_word(
                                LocatedValue(elem_b_loc, &elem_a).into(),
                                RW::WRITE,
                                rw_operations,
                            );
                            globals::emit_global_ops_for_word(
                                LocatedValue(elem_a_loc, &elem_b).into(),
                                RW::WRITE,
                                rw_operations,
                            );
                            execution_step.auxiliary_5 = Some(Value::bool(true));
                        } else {
                            locals::emit_locals_ops_for_word(
                                LocatedValue(elem_a_loc.clone(), &elem_a).into(),
                                RW::READ,
                                rw_operations,
                            );
                            locals::emit_locals_ops_for_word(
                                LocatedValue(elem_b_loc.clone(), &elem_b).into(),
                                RW::READ,
                                rw_operations,
                            );
                            locals::emit_locals_ops_for_word(
                                LocatedValue(elem_b_loc, &elem_a).into(),
                                RW::WRITE,
                                rw_operations,
                            );
                            locals::emit_locals_ops_for_word(
                                LocatedValue(elem_a_loc, &elem_b).into(),
                                RW::WRITE,
                                rw_operations,
                            );
                            execution_step.auxiliary_5 = Some(Value::bool(false));
                        }

                        let word_a_element_count = Word::from(&elem_a).0.len();
                        let word_b_element_count = Word::from(&elem_b).0.len();

                        execution_step.auxiliary_1 = Some(Value::u64(si.0 as u64));
                        execution_step.auxiliary_2 = Some(Value::u64(word_a_element_count as u64));
                        execution_step.auxiliary_3 = Some(Value::u64(word_b_element_count as u64));
                        execution_step.auxiliary_4 = Some(Value::u64(ref_val_flattened_len as u64));

                        vec_ref.swap(idx_a, idx_b)
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
    CallGeneric(FunctionInstantiationIndex, ExecutionStep<F>),
}
