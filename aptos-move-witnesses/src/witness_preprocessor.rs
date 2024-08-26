use crate::exec_state::ExecutionState;
use crate::exec_state::ExecutionState::{
    VecSwapStage2, VecSwapStage3, VecSwapStage4, VecSwapStage5,
};
use crate::static_info::StaticInfo;
use crate::step_state::{
    CallerData, ExecStepState, LocalReadWrite, MemoryOp, RetExtraAssignData, Slot, StackPop,
    StackPush, StageState, StepState, Version,
};
use crate::types::sub_index::SubIndex;
use crate::types::value_header::ValueHeader;
use crate::types::word::Word;
use crate::utils::flatten::Flatten;
use crate::witness_preprocessor::to_u256::ToU256;
use move_vm_runtime::witnessing::traced_value::{Integer, Reference, SimpleValue, ValueItem};
use move_vm_runtime::witnessing::{BinaryIntegerOperationType, Footprint, Operation};
use move_vm_types::values::IntegerValue;
use std::collections::BTreeMap;
use std::ops::{Add, Deref, DerefMut, Div, Mul, Rem, Sub};

#[derive(Default)]
pub struct WitnessPreProcessor {
    clk: Version,
    // track versions of each stack value
    version_stack: Vec<Version>,
    call_stack_versions: Vec<Version>,
    locals: Locals,
}
impl WitnessPreProcessor {
    pub fn pre_process(
        mut self,
        traces: &Vec<crate::Footprint>,
        static_info: &StaticInfo,
    ) -> Vec<StageState> {
        let mut exec_states = vec![];
        for footprint in traces {
            let mut states = self.process_footprint(footprint, static_info);
            exec_states.append(&mut states);
            self.clk += 1;
        }
        // nop ops to write (final_set, init_set)
        exec_states.push(StageState {
            step_states: vec![ExecStepState {
                step_state: StepState::default().change_clk(self.clk),
                memory_ops: self
                    .locals
                    .to_write_set()
                    .into_iter()
                    .map(|l| MemoryOp(None, None, Some(l)))
                    .collect(),
            }],
            extra_data: None,
        });
        exec_states
    }

    fn process_footprint(
        &mut self,
        trace: &Footprint,
        static_info: &StaticInfo,
    ) -> Vec<StageState> {
        let sp = trace.stack_pointer as u64;
        let current_frame_index = trace.frame_index;
        match &trace.data {
            Operation::LdSimple(v) => {
                let step_state = StepState::new(self.clk, ExecutionState::LdSimple, trace);
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp + 1,
                    sub_index: SubIndex::default(),
                    value: v.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![MemoryOp(None, Some(stack_push), None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::LdTrue | Operation::LdFalse => {
                let (state, out) = match &trace.data {
                    Operation::LdTrue => (ExecutionState::LdTrue, true),
                    Operation::LdFalse => (ExecutionState::LdTrue, false),
                    _ => unreachable!(),
                };

                let step_state = StepState::new(self.clk, state, trace);
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp + 1,
                    sub_index: SubIndex::default(),
                    value: out.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![MemoryOp(None, Some(stack_push), None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::LdConst { const_pool_index } => {
                let module_index = static_info
                    .module_id_mapping
                    .get_module_index(trace.module_id.as_ref().unwrap());
                let constant = static_info
                    .get_constant(module_index, *const_pool_index as usize)
                    .unwrap_or_else(|| panic!("cannot find constant {:?}", *const_pool_index))
                    .flatten();
                let step_state = StepState::new(self.clk, ExecutionState::LdConst, trace);

                self.version_stack.push(self.clk);
                let memory_ops = constant
                    .iter()
                    .map(|item| {
                        let stack_push = StackPush {
                            index: sp + 1,
                            sub_index: item.sub_index.clone().into(),
                            value: item.value.clone().into(),
                            value_header: item.header,
                            version: self.clk,
                        };
                        MemoryOp(None, Some(stack_push), None)
                    })
                    .collect();
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::CastU8 { origin }
            | Operation::CastU16 { origin }
            | Operation::CastU32 { origin }
            | Operation::CastU64 { origin }
            | Operation::CastU128 { origin }
            | Operation::CastU256 { origin } => {
                let step_state = StepState::new(self.clk, ExecutionState::Cast, trace);
                // convert to U256 and then do casting, to prevent witnessing from being interrupted.
                let new = match &trace.data {
                    Operation::CastU8 { origin } => {
                        SimpleValue::U8(origin.to_u256().unchecked_as_u8())
                    }
                    Operation::CastU16 { origin } => {
                        SimpleValue::U16(origin.to_u256().unchecked_as_u16())
                    }
                    Operation::CastU32 { origin } => {
                        SimpleValue::U32(origin.to_u256().unchecked_as_u32())
                    }
                    Operation::CastU64 { origin } => {
                        SimpleValue::U64(origin.to_u256().unchecked_as_u64())
                    }
                    Operation::CastU128 { origin } => {
                        SimpleValue::U128(origin.to_u256().unchecked_as_u128())
                    }
                    Operation::CastU256 { origin } => SimpleValue::U256(origin.to_u256()),
                    _ => unreachable!(),
                }; //TODO: optimization: convert to word directly
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: origin.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: new.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![MemoryOp(Some(stack_pop), Some(stack_push), None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::Pop { poped_value } => {
                let step_state = StepState::new(self.clk, ExecutionState::Pop, trace);
                let value_version = self.version_stack.pop().unwrap();
                let memory_ops = poped_value
                    .iter()
                    .map(|item| {
                        let stack_pop = StackPop {
                            index: sp,
                            sub_index: item.sub_index.clone().into(),
                            value: item.value.clone().into(),
                            value_header: item.header,
                            version: value_version,
                        };
                        MemoryOp(Some(stack_pop), None, None)
                    })
                    .collect();
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::BrTrue {
                cond_val,
                code_offset,
            }
            | Operation::BrFalse {
                cond_val,
                code_offset,
            } => {
                let state = match &trace.data {
                    Operation::BrTrue { .. } => ExecutionState::BrTrue,
                    Operation::BrFalse { .. } => ExecutionState::BrFalse,
                    _ => unreachable!(),
                };
                let step_state =
                    StepState::new(self.clk, state, trace).set_aux0(*code_offset as u128);
                let value_version = self.version_stack.pop().unwrap();
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: (*cond_val).into(),
                    value_header: false,
                    version: value_version,
                };
                let memory_ops = vec![MemoryOp(Some(stack_pop), None, None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::StLoc {
                local_index,
                old_local,
                new_value,
            } => {
                // stage1 of st_loc.
                let step_state = StepState::new(self.clk, ExecutionState::StoreLocStage1, trace);
                let stage1_state = {
                    let header_check_sub_index = SubIndex::default();

                    let header_slot = self.locals.peek_local_slot(
                        current_frame_index,
                        *local_index as usize,
                        &header_check_sub_index, // TODO: check root header's sub index.
                    );
                    let old_value_invalid = match header_slot {
                        None => true,
                        Some(s) => s.value_invalid,
                    };
                    let memory_ops = if old_value_invalid {
                        let (old_slot, new_slot) = self.locals.read_local_slot_with_clk(
                            current_frame_index,
                            *local_index as usize,
                            &header_check_sub_index,
                            self.clk,
                        );
                        vec![MemoryOp(
                            None,
                            None,
                            Some(LocalReadWrite::new(
                                current_frame_index as u16,
                                *local_index as u16,
                                header_check_sub_index,
                                old_slot,
                                new_slot,
                            )),
                        )]
                    } else {
                        debug_assert!(old_local.is_some());
                        if let Some(old_local) = old_local {
                            old_local
                                .iter()
                                .map(|item| {
                                    let (old_, new_) = self.locals.write_local_slot_with_clk(
                                        current_frame_index,
                                        *local_index as usize,
                                        &item.sub_index.clone().into(),
                                        item.value.clone().into(),
                                        item.header,
                                        true,
                                        self.clk,
                                    );
                                    LocalReadWrite::new(
                                        current_frame_index as u16,
                                        *local_index as u16,
                                        item.sub_index.clone().into(),
                                        old_,
                                        new_,
                                    )
                                })
                                .map(|local_op| MemoryOp(None, None, Some(local_op)))
                                .collect()
                        } else {
                            unreachable!()
                        }
                    };
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };

                self.clk += 1;

                let step_state = step_state
                    .change_state(ExecutionState::StoreLocStage2)
                    .change_clk(self.clk);

                let value_version = self.version_stack.pop().unwrap();
                let memory_ops: Vec<_> = new_value
                    .iter()
                    .map(|value_item| {
                        let stack_pop = StackPop {
                            index: step_state.sp,
                            sub_index: value_item.sub_index.clone().into(),
                            value: value_item.value.clone().into(),
                            value_header: value_item.header,
                            version: value_version,
                        };
                        let (old_, new_) = self.locals.write_local_slot_with_clk(
                            current_frame_index,
                            *local_index as u16 as usize,
                            &stack_pop.sub_index,
                            stack_pop.value.clone().into(),
                            stack_pop.value_header,
                            false,
                            self.clk,
                        );
                        let local_op = LocalReadWrite::new(
                            current_frame_index as u16,
                            *local_index as u16,
                            stack_pop.sub_index.clone(),
                            old_,
                            new_,
                        );
                        MemoryOp(Some(stack_pop), None, Some(local_op))
                    })
                    .collect();
                let stage2_state = ExecStepState {
                    step_state,
                    memory_ops,
                };
                vec![
                    StageState {
                        step_states: vec![stage1_state],
                        extra_data: None,
                    },
                    StageState {
                        step_states: vec![stage2_state],
                        extra_data: None,
                    },
                ]
            }
            Operation::MoveLoc { local_index, local } => {
                let step_state = StepState::new(self.clk, ExecutionState::MoveLoc, trace);
                let memory_ops = local
                    .iter()
                    .map(|item| {
                        // invalidate the local
                        let (old_, new_) = self.locals.write_local_slot_with_clk(
                            current_frame_index,
                            *local_index as usize,
                            &item.sub_index.clone().into(),
                            item.value.clone().into(),
                            item.header,
                            true,
                            self.clk,
                        );
                        // TODO: check old_ == local[sub_index]
                        let stack_push = StackPush {
                            index: step_state.sp + 1,
                            sub_index: item.sub_index.clone().into(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            current_frame_index as u16,
                            *local_index as u16,
                            item.sub_index.clone().into(),
                            old_,
                            new_,
                        );
                        MemoryOp(None, Some(stack_push), Some(local_op))
                    })
                    .collect();
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::CopyLoc { local_index, local } => {
                let step_state = StepState::new(self.clk, ExecutionState::CopyLoc, trace);
                let memory_ops = local
                    .iter()
                    .map(|item| {
                        // invalidate the local
                        let (old_, new_) = self.locals.read_local_slot_with_clk(
                            current_frame_index,
                            *local_index as usize,
                            &item.sub_index.clone().into(),
                            self.clk,
                        );
                        // TODO: check old_ == local[sub_index]
                        let stack_push = StackPush {
                            index: step_state.sp + 1,
                            sub_index: item.sub_index.clone().into(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            current_frame_index as u16,
                            *local_index as u16,
                            item.sub_index.clone().into(),
                            old_,
                            new_,
                        );
                        MemoryOp(None, Some(stack_push), Some(local_op))
                    })
                    .collect();
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::VecLen { si, vec_ref, len } => {
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: vec_ref.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: Integer::U64(*len).into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let (old_slot, new_slot) = self.locals.read_local_slot_with_clk(
                    vec_ref.frame_index,
                    vec_ref.local_index,
                    &vec_ref.sub_index.clone().into(),
                    self.clk,
                );
                let local_op = LocalReadWrite::new(
                    vec_ref.frame_index as u16,
                    vec_ref.local_index as u16,
                    vec_ref.sub_index.clone().into(),
                    old_slot,
                    new_slot,
                );
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, ExecutionState::VecLen, trace),
                        memory_ops: vec![MemoryOp(
                            Some(stack_pop),
                            Some(stack_push),
                            Some(local_op),
                        )],
                    }],
                    extra_data: None,
                }]
            }
            Operation::BorrowLoc { imm, local_index } => {
                let exec_state = ExecutionState::BorrowLoc;
                let loc_ref = Reference {
                    frame_index: current_frame_index,
                    local_index: *local_index as usize,
                    sub_index: vec![0],
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp + 1,
                    sub_index: SubIndex::default(),
                    value: loc_ref.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, exec_state, trace),
                        memory_ops: vec![MemoryOp(None, Some(stack_push), None)],
                    }],
                    extra_data: None,
                }]
            }
            Operation::BorrowField {
                imm,
                fh_idx,
                reference,
                field_offset,
            } => {
                let exec_state = ExecutionState::BorrowField;
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: reference.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let mut sub_index = reference.sub_index.clone();
                sub_index.push((*field_offset + 1).try_into().unwrap());
                let field_ref = Reference {
                    frame_index: reference.frame_index,
                    local_index: reference.local_index,
                    sub_index,
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: field_ref.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, exec_state, trace),
                        memory_ops: vec![MemoryOp(Some(stack_pop), Some(stack_push), None)],
                    }],
                    extra_data: None,
                }]
            }
            Operation::VecBorrow {
                si,
                imm,
                idx,
                vec_ref,
            } => {
                let exec_state = ExecutionState::VecBorrow;
                let stack_pop_idx = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: Integer::U64(*idx).into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_vec_ref = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: vec_ref.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let mut sub_index = vec_ref.sub_index.clone();
                sub_index.push((*idx + 1).try_into().unwrap());
                let element_ref = Reference {
                    frame_index: vec_ref.frame_index,
                    local_index: vec_ref.local_index,
                    sub_index,
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: element_ref.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, exec_state, trace),
                        memory_ops: vec![
                            MemoryOp(Some(stack_pop_idx), None, None),
                            MemoryOp(Some(stack_pop_vec_ref), Some(stack_push), None),
                        ],
                    }],
                    extra_data: None,
                }]
            }
            Operation::Neq { lhs, rhs } | Operation::Eq { lhs, rhs } => {
                let step_state = StepState::new(self.clk, ExecutionState::EqStage1, trace);
                let stage1_state = {
                    let value_version = self.version_stack.pop().unwrap();
                    let memory_ops = rhs
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: value_version,
                            };
                            MemoryOp(Some(stack_pop), None, None)
                        })
                        .collect::<Vec<_>>();
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };
                self.clk += 1;
                let stage2_state = {
                    let step_state = step_state
                        .change_state(ExecutionState::EqStage2)
                        .change_clk(self.clk)
                        .dec_sp(1);
                    let value_version = self.version_stack.pop().unwrap();
                    let mut memory_ops = lhs
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: value_version,
                            };
                            MemoryOp(Some(stack_pop), None, None)
                        })
                        .collect::<Vec<_>>();
                    let mut lhs_sorted = lhs.clone();
                    lhs_sorted.sort_by_key(|item| item.sub_index.clone());
                    let mut rhs_sorted = rhs.clone();
                    rhs_sorted.sort_by_key(|item| item.sub_index.clone());
                    let out = if matches!(&trace.data, Operation::Eq { .. }) {
                        lhs_sorted == rhs_sorted
                    } else {
                        lhs_sorted != rhs_sorted
                    };
                    let _ = memory_ops.last_mut().unwrap().1.insert(StackPush {
                        index: step_state.sp,
                        sub_index: SubIndex::default(),
                        value: out.into(),
                        value_header: false,
                        version: self.clk,
                    });
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };
                vec![
                    StageState {
                        step_states: vec![stage1_state],
                        extra_data: None,
                    },
                    StageState {
                        step_states: vec![stage2_state],
                        extra_data: None,
                    },
                ]
            }
            Operation::ReadRef { reference, value } => {
                let step_state = StepState::new(self.clk, ExecutionState::ReadRef, trace);
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: reference.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let memory_ops = value
                    .iter()
                    .enumerate()
                    .map(|(idx, item)| {
                        let (old_, new_) = self.locals.read_local_slot_with_clk(
                            reference.frame_index,
                            reference.local_index,
                            &item.sub_index.clone().into(),
                            self.clk,
                        );
                        let stack_push = StackPush {
                            index: sp,
                            sub_index: item.sub_index.clone().into(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            reference.frame_index.try_into().unwrap(),
                            reference.local_index.try_into().unwrap(),
                            item.sub_index.clone().into(),
                            old_,
                            new_,
                        );
                        let stack_pop_opt = if idx == 0 {
                            Some(stack_pop.clone())
                        } else {
                            None
                        };
                        MemoryOp(stack_pop_opt, Some(stack_push), Some(local_op))
                    })
                    .collect();
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::WriteRef {
                reference,
                old_value,
                new_value,
            } => {
                // stage1: STAGE_POP_REF_AND_INVALIDATE_OLD
                let step_state = StepState::new(self.clk, ExecutionState::WriteRefStage1, trace);
                let stage1_state = {
                    let stack_pop = StackPop {
                        index: sp,
                        sub_index: SubIndex::default(),
                        value: reference.into(),
                        value_header: false,
                        version: self.version_stack.pop().unwrap(),
                    };
                    let memory_ops = old_value
                        .iter()
                        .enumerate()
                        .map(|(idx, item)| {
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                reference.frame_index,
                                reference.local_index,
                                &item.sub_index.clone().into(),
                                item.value.clone().into(),
                                item.header,
                                true,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                reference.frame_index.try_into().unwrap(),
                                reference.local_index.try_into().unwrap(),
                                item.sub_index.clone().into(),
                                old_,
                                new_,
                            );
                            let stack_pop_opt = if idx == 0 {
                                Some(stack_pop.clone())
                            } else {
                                None
                            };
                            MemoryOp(stack_pop_opt, None, Some(local_op))
                        })
                        .collect();
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };
                // stage2: STAGE_POP_NEW_VALUE_AND_WRITE
                self.clk += 1;
                let value_version = self.version_stack.pop().unwrap();
                let step_state = step_state
                    .change_state(ExecutionState::WriteRefStage2)
                    .change_clk(self.clk)
                    .dec_sp(1);
                let stage2_state = {
                    let memory_ops: Vec<_> = new_value
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: value_version,
                            };
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                reference.frame_index,
                                reference.local_index,
                                &stack_pop.sub_index,
                                stack_pop.value.clone().into(),
                                stack_pop.value_header,
                                false,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                reference.frame_index.try_into().unwrap(),
                                reference.local_index.try_into().unwrap(),
                                stack_pop.sub_index.clone(),
                                old_,
                                new_,
                            );
                            MemoryOp(Some(stack_pop), None, Some(local_op))
                        })
                        .collect();
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };
                // stage3: STAGE_UPDATE_PARENT
                self.clk += 1;
                let step_state = step_state
                    .change_state(ExecutionState::WriteRefStage3)
                    .change_clk(self.clk)
                    .dec_sp(1);
                let stage3_state = {
                    let depth = SubIndex::from(reference.sub_index.clone()).depth();
                    let parents = SubIndex::from(reference.sub_index.clone()).parents();
                    let memory_ops: Vec<_> = (0..depth)
                        .map(|i| {
                            // we come here, then depth >= 1, reference.sub_index != 0
                            // at least we have one parent
                            let sub_index = &parents[i];
                            let parent_value = self
                                .locals
                                .peek_local_slot(
                                    reference.frame_index,
                                    reference.local_index,
                                    sub_index,
                                )
                                .unwrap()
                                .value
                                .clone();
                            let len = ValueHeader::from(parent_value).len;

                            // TODO: save flen in the traced value while footprinting?
                            let members = self.locals.members(
                                reference.frame_index,
                                reference.local_index,
                                sub_index,
                            );
                            let flen = match members {
                                Some(members) => members.len(),
                                None => unreachable!(),
                            };

                            let new_parent_value = ValueHeader::new(flen, len as usize);
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                reference.frame_index,
                                reference.local_index,
                                sub_index,
                                new_parent_value.into(),
                                true,
                                false,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                reference.frame_index.try_into().unwrap(),
                                reference.local_index.try_into().unwrap(),
                                sub_index.clone(),
                                old_,
                                new_,
                            );
                            MemoryOp(None, None, Some(local_op))
                        })
                        .collect();
                    ExecStepState {
                        step_state,
                        memory_ops,
                    }
                };
                vec![
                    StageState {
                        step_states: vec![stage1_state],
                        extra_data: None,
                    },
                    StageState {
                        step_states: vec![stage2_state],
                        extra_data: None,
                    },
                    StageState {
                        step_states: vec![stage3_state],
                        extra_data: None,
                    },
                ]
            }
            Operation::Pack { sd_idx, args } => {
                let step_state = StepState::new(self.clk, ExecutionState::Pack, trace);

                let flen = args.iter().fold(0usize, |sum, arg| sum + arg.len()) + 1;
                let len = args.len();

                let mut memory_ops = vec![MemoryOp(
                    None,
                    Some(StackPush {
                        index: step_state.sp + 1 - len as u64,
                        sub_index: SubIndex::default(),
                        value: ValueHeader::new(flen, len).into(),
                        value_header: true,
                        version: step_state.clk,
                    }),
                    None,
                )];
                for (i, arg) in args.iter().enumerate().rev() {
                    let version = self.version_stack.pop().unwrap();
                    memory_ops.extend(arg.iter().map(|item| {
                        let stack_pop = StackPop {
                            index: step_state.sp - i as u64,
                            sub_index: item.sub_index.clone().into(),
                            value: item.value.clone().into(),
                            value_header: item.header,
                            version,
                        };
                        let stack_push = StackPush {
                            index: step_state.sp + 1 - len as u64,
                            sub_index: {
                                let mut sub_index = SubIndex::new(item.sub_index.clone());
                                sub_index.insert(0, (i + 1).try_into().unwrap());
                                sub_index
                            },
                            value: item.value.clone().into(),
                            value_header: item.header,
                            version: step_state.clk,
                        };
                        MemoryOp(Some(stack_pop), Some(stack_push), None)
                    }));
                }
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::Unpack { sd_idx, arg } => {
                debug_assert!(!arg.is_empty());
                let step_state = StepState::new(self.clk, ExecutionState::UnpackStage1, trace);
                let arg_header = arg.first().unwrap();
                let arg_version = self.version_stack.pop().unwrap();
                let stack_pop = StackPop {
                    index: step_state.sp,
                    sub_index: arg_header.sub_index.clone().into(),
                    value: arg_header.value.clone().into(),
                    value_header: arg_header.header,
                    version: arg_version,
                };
                let mut stages = vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops: vec![MemoryOp(Some(stack_pop), None, None)],
                    }],
                    extra_data: None,
                }];

                let mut fields = arg.iter().skip(1).fold(
                    BTreeMap::<_, Vec<ValueItem>>::new(),
                    |mut acc, item| {
                        let field_index = item.sub_index.first().cloned().unwrap();
                        acc.entry(field_index).or_default().push(item.clone());
                        acc
                    },
                );

                // sort the items
                fields
                    .values_mut()
                    .for_each(|v| v.sort_by_key(|item| item.sub_index.clone()));

                assert_eq!(
                    fields
                        .keys()
                        .cloned()
                        .map(|k| k as usize)
                        .collect::<Vec<_>>(),
                    (1..=fields.len()).collect::<Vec<_>>()
                );

                if !fields.is_empty() {
                    // ----- stage2
                    for (field_index, field) in fields.into_iter().rev() {
                        self.clk += 1;
                        let step_state = step_state
                            .change_state(ExecutionState::UnpackStage2)
                            .change_clk(self.clk);
                        let memory_ops = field
                            .into_iter()
                            .map(|item| {
                                let stack_pop = StackPop {
                                    index: step_state.sp,
                                    sub_index: item.sub_index.clone().into(),
                                    value: item.value.clone().into(),
                                    value_header: item.header,
                                    version: arg_version,
                                };
                                let stack_push = StackPush {
                                    index: step_state.sp + field_index as u64 - 1,
                                    sub_index: {
                                        let mut sub_index = SubIndex::from(item.sub_index);
                                        sub_index.remove(0); // drop the field_index
                                        sub_index
                                    },
                                    value: item.value.clone().into(),
                                    value_header: item.header,
                                    version: step_state.clk,
                                };
                                self.version_stack.push(step_state.clk);

                                MemoryOp(Some(stack_pop), Some(stack_push), None)
                            })
                            .collect();
                        stages.push(StageState {
                            step_states: vec![ExecStepState {
                                step_state,
                                memory_ops,
                            }],
                            extra_data: None,
                        });
                    }
                }
                stages
            }
            Operation::VecSwap {
                si,
                vec_ref,
                vec_len,
                idx1,
                idx2,
                idx1_elem,
                idx2_elem,
            } => {
                let mut step_state = StepState::new(self.clk, ExecutionState::VecSwapStage1, trace);

                let stage1 = {
                    let states = [
                        SimpleValue::U64(*idx2),
                        SimpleValue::U64(*idx1),
                        SimpleValue::Reference(vec_ref.clone()),
                    ]
                    .map(|value| {
                        let s = ExecStepState {
                            step_state,
                            memory_ops: vec![MemoryOp(
                                Some(StackPop {
                                    index: step_state.sp,
                                    sub_index: SubIndex::default(),
                                    value: value.into(),
                                    value_header: false,
                                    version: self.version_stack.pop().unwrap(),
                                }),
                                None,
                                None,
                            )],
                        };
                        step_state = step_state.dec_sp(1);
                        s
                    })
                    .to_vec();
                    StageState {
                        step_states: states,
                        extra_data: None,
                    }
                };

                let mut stages = vec![stage1];
                // stage 2/3
                for (idx, idx_elem, new_state) in [
                    (idx1, idx1_elem, VecSwapStage2),
                    (idx2, idx2_elem, VecSwapStage3),
                ] {
                    self.clk += 1;
                    step_state = step_state.change_state(new_state).change_clk(self.clk);
                    let idx_items_sub_index_prefix = SubIndex::from(vec_ref.sub_index.clone())
                        .concat(&vec![*idx as usize].into());
                    let memory_ops = idx_elem
                        .iter()
                        .map(|item| {
                            let item_sub_index =
                                idx_items_sub_index_prefix.concat(&item.sub_index.clone().into());
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &item_sub_index,
                                item.value.clone().into(),
                                item.header,
                                true,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                vec_ref.frame_index as u16,
                                vec_ref.local_index as u16,
                                item_sub_index,
                                old_,
                                new_,
                            );
                            let stack_push = StackPush {
                                index: step_state.sp + 1,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: self.clk,
                            };
                            MemoryOp(None, Some(stack_push), Some(local_op))
                        })
                        .collect();
                    self.version_stack.push(self.clk);

                    stages.push(StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    });
                    step_state = step_state.inc_sp(1);
                }

                // stage4/5
                for (idx, idx_elem, new_state) in [
                    (idx1, idx2_elem, VecSwapStage4),
                    (idx2, idx1_elem, VecSwapStage5),
                ] {
                    self.clk += 1;
                    step_state = step_state.change_state(new_state).change_clk(self.clk);
                    let idx_items_sub_index_prefix = SubIndex::from(vec_ref.sub_index.clone())
                        .concat(&vec![*idx as usize].into());
                    let stack_value_version = self.version_stack.pop().unwrap();
                    let memory_ops = idx_elem
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: stack_value_version,
                            };
                            let item_sub_index =
                                idx_items_sub_index_prefix.concat(&item.sub_index.clone().into());
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &item_sub_index,
                                item.value.clone().into(),
                                item.header,
                                false,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                vec_ref.frame_index as u16,
                                vec_ref.local_index as u16,
                                item_sub_index,
                                old_,
                                new_,
                            );

                            MemoryOp(Some(stack_pop), None, Some(local_op))
                        })
                        .collect();
                    stages.push(StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    });
                    step_state = step_state.dec_sp(1);
                }
                stages
            }
            Operation::VecPopBack {
                si,
                vec_len,
                vec_ref,
                elem,
            } => {
                let step_state = StepState::new(self.clk, ExecutionState::VecPopBackStage1, trace);

                let stage1 = {
                    let ref_pop = StackPop {
                        index: step_state.sp,
                        sub_index: SubIndex::default(),
                        value: vec_ref.into(),
                        value_header: false,
                        version: self.version_stack.pop().unwrap(),
                    };
                    let mut memory_ops = vec![];

                    let mut parents = SubIndex::from(vec_ref.sub_index.clone()).parents();
                    // insert itself
                    parents.insert(0, vec_ref.sub_index.clone().into());
                    for (i, parent_sub_index) in parents.into_iter().enumerate().rev() {
                        let parent_header = self
                            .locals
                            .peek_local_slot(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &parent_sub_index,
                            )
                            .unwrap()
                            .value
                            .clone();
                        let parent_header = ValueHeader::from(parent_header);
                        let new_header = ValueHeader::new(
                            parent_header.flen as usize - elem.len(),
                            if i == 0 {
                                parent_header.len as usize - 1
                            } else {
                                parent_header.len as usize
                            },
                        )
                        .into();
                        let (old_, new_) = self.locals.write_local_slot_with_clk(
                            vec_ref.frame_index,
                            vec_ref.local_index,
                            &parent_sub_index,
                            new_header,
                            true,
                            false,
                            self.clk,
                        );
                        let local_op = LocalReadWrite::new(
                            vec_ref.frame_index as u16,
                            vec_ref.local_index as u16,
                            parent_sub_index.clone(),
                            old_,
                            new_,
                        );
                        if i == 0 {
                            debug_assert!(local_op.read_value_header);
                            debug_assert_eq!(
                                *vec_len,
                                ValueHeader::from(local_op.read_value.clone()).len as u64
                            );
                        }
                        memory_ops.push(MemoryOp(None, None, Some(local_op)));
                    }

                    memory_ops[0].0 = Some(ref_pop);

                    StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    }
                };

                self.clk += 1;

                let stage2 = {
                    self.version_stack.push(self.clk);
                    let step_state = step_state.change_state(ExecutionState::VecPopBackStage2);

                    let memory_ops = elem
                        .iter()
                        .map(|item| {
                            let local_item_sub_index = SubIndex::from(vec_ref.sub_index.clone())
                                .concat(
                                    &SubIndex::from(vec![*vec_len as usize])
                                        .concat(&item.sub_index.clone().into()),
                                );
                            // invalidate local slot
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &local_item_sub_index,
                                item.value.clone().into(),
                                item.header,
                                true,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                vec_ref.frame_index as u16,
                                vec_ref.local_index as u16,
                                local_item_sub_index,
                                old_,
                                new_,
                            );
                            let stack_push = StackPush {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: self.version_stack.last().cloned().unwrap(),
                            };
                            MemoryOp(None, Some(stack_push), Some(local_op))
                        })
                        .collect();
                    StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    }
                };
                vec![stage1, stage2]
            }
            Operation::VecPushBack {
                si,
                vec_len,
                vec_ref,
                elem,
            } => {
                let step_state = StepState::new(self.clk, ExecutionState::VecPushBackStage1, trace);

                let stage1 = {
                    let ref_pop = StackPop {
                        index: step_state.sp,
                        sub_index: SubIndex::default(),
                        value: vec_ref.into(),
                        value_header: false,
                        version: self.version_stack.pop().unwrap(),
                    };
                    let mut memory_ops = vec![];

                    let mut parents = SubIndex::from(vec_ref.sub_index.clone()).parents();
                    // insert itself
                    parents.insert(0, vec_ref.sub_index.clone().into());
                    for (i, parent_sub_index) in parents.into_iter().enumerate().rev() {
                        let parent_header = self
                            .locals
                            .peek_local_slot(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &parent_sub_index,
                            )
                            .unwrap()
                            .value
                            .clone();
                        let parent_header = ValueHeader::from(parent_header);
                        let new_header = ValueHeader::new(
                            parent_header.flen as usize + elem.len(),
                            if i == 0 {
                                parent_header.len as usize + 1
                            } else {
                                parent_header.len as usize
                            },
                        )
                        .into();
                        let (old_, new_) = self.locals.write_local_slot_with_clk(
                            vec_ref.frame_index,
                            vec_ref.local_index,
                            &parent_sub_index,
                            new_header,
                            true,
                            false,
                            self.clk,
                        );
                        let local_op = LocalReadWrite::new(
                            vec_ref.frame_index as u16,
                            vec_ref.local_index as u16,
                            parent_sub_index.clone(),
                            old_,
                            new_,
                        );
                        if i == 0 {
                            debug_assert!(local_op.read_value_header);
                            debug_assert_eq!(
                                *vec_len,
                                ValueHeader::from(local_op.read_value.clone()).len as u64
                            );
                        }
                        memory_ops.push(MemoryOp(None, None, Some(local_op)));
                    }

                    memory_ops[0].0 = Some(ref_pop);

                    StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    }
                };

                self.clk += 1;

                let stage2 = {
                    let step_state = step_state.change_state(ExecutionState::VecPushBackStage2);

                    let version = self.version_stack.pop().unwrap();

                    let memory_ops = elem
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp - 1,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version,
                            };
                            let local_item_sub_index = SubIndex::from(vec_ref.sub_index.clone())
                                .concat(
                                    &SubIndex::from(vec![*vec_len as usize + 1])
                                        .concat(&item.sub_index.clone().into()),
                                );
                            // invalidate local slot
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &local_item_sub_index,
                                item.value.clone().into(),
                                item.header,
                                false,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                vec_ref.frame_index as u16,
                                vec_ref.local_index as u16,
                                local_item_sub_index,
                                old_,
                                new_,
                            );

                            MemoryOp(Some(stack_pop), None, Some(local_op))
                        })
                        .collect();
                    StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    }
                };
                vec![stage1, stage2]
            }
            Operation::And { lhs, rhs } | Operation::Or { lhs, rhs } => {
                let (is_and, out) = match &trace.data {
                    Operation::And { lhs, rhs } => (true, *lhs && *rhs),
                    Operation::Or { lhs, rhs } => (false, *lhs || *rhs),
                    _ => unreachable!(),
                };
                let step_state =
                    StepState::new(self.clk, ExecutionState::AndOr, trace).set_aux0(is_and as u128);

                let stack_pop_rhs = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: (*rhs).into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_lhs = StackPop {
                    index: sp - 1,
                    sub_index: SubIndex::default(),
                    value: (*lhs).into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp - 1,
                    sub_index: SubIndex::default(),
                    value: out.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![
                    MemoryOp(Some(stack_pop_rhs), None, None),
                    MemoryOp(Some(stack_pop_lhs), Some(stack_push), None),
                ];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::Not { value } => {
                let step_state = StepState::new(self.clk, ExecutionState::Not, trace);
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: (*value).into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: (!(*value)).into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![MemoryOp(Some(stack_pop), Some(stack_push), None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                    extra_data: None,
                }]
            }
            Operation::BinaryOp { ty, rhs, lhs } => {
                let num_bytes = match (lhs, rhs) {
                    (Integer::U8(_l), Integer::U8(_r)) => 1usize,
                    (Integer::U16(_l), Integer::U16(_r)) => 2usize,
                    (Integer::U32(_l), Integer::U32(_r)) => 4usize,
                    (Integer::U64(_l), Integer::U64(_r)) => 8usize,
                    (Integer::U128(_l), Integer::U128(_r)) => 16usize,
                    (Integer::U256(_l), Integer::U256(_r)) => 32usize,
                    _ => unreachable!(),
                };

                let (out, step_state) = match ty {
                    // while calculating the result, wrapping around at the boundary of the u256,
                    // to prevent overflow from stopping the computing.
                    BinaryIntegerOperationType::Add => {
                        let output = lhs.to_u256().add(rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::AddSub, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Sub => {
                        let output = lhs.to_u256().sub(rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::AddSub, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Mul => {
                        let output = lhs.to_u256().mul(rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::MulDivMod, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Div => {
                        let output = lhs.to_u256().div(rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::MulDivMod, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Mod => {
                        let output = lhs.to_u256().rem(rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::MulDivMod, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Lt => {
                        let output = IntegerValue::from(lhs.clone())
                            .lt(IntegerValue::from(rhs.clone()))
                            .expect("should not fail");
                        let step_state = StepState::new(self.clk, ExecutionState::Lt, trace);
                        (SimpleValue::Bool(output), step_state)
                    }
                    BinaryIntegerOperationType::Gt => {
                        let output = IntegerValue::from(lhs.clone())
                            .gt(IntegerValue::from(rhs.clone()))
                            .expect("should not fail");
                        let step_state = StepState::new(self.clk, ExecutionState::Gt, trace);
                        (SimpleValue::Bool(output), step_state)
                    }
                    BinaryIntegerOperationType::Le => {
                        let output = IntegerValue::from(lhs.clone())
                            .le(IntegerValue::from(rhs.clone()))
                            .expect("should not fail");
                        let step_state = StepState::new(self.clk, ExecutionState::Le, trace);
                        (SimpleValue::Bool(output), step_state)
                    }
                    BinaryIntegerOperationType::Ge => {
                        let output = IntegerValue::from(lhs.clone())
                            .ge(IntegerValue::from(rhs.clone()))
                            .expect("should not fail");
                        let step_state = StepState::new(self.clk, ExecutionState::Ge, trace);
                        (SimpleValue::Bool(output), step_state)
                    }
                    BinaryIntegerOperationType::BitAnd => {
                        let output: Integer = IntegerValue::from(lhs.clone())
                            .bit_and(IntegerValue::from(rhs.clone()))
                            .expect("should not fail")
                            .into();
                        let step_state = StepState::new(self.clk, ExecutionState::Bitwise, trace);
                        (SimpleValue::from(output), step_state)
                    }
                    BinaryIntegerOperationType::BitOr => {
                        let output: Integer = IntegerValue::from(lhs.clone())
                            .bit_or(IntegerValue::from(rhs.clone()))
                            .expect("should not fail")
                            .into();
                        let step_state = StepState::new(self.clk, ExecutionState::Bitwise, trace);
                        (SimpleValue::from(output), step_state)
                    }
                    BinaryIntegerOperationType::Xor => {
                        let output: Integer = IntegerValue::from(lhs.clone())
                            .bit_xor(IntegerValue::from(rhs.clone()))
                            .expect("should not fail")
                            .into();
                        let step_state = StepState::new(self.clk, ExecutionState::Bitwise, trace);
                        (SimpleValue::from(output), step_state)
                    }
                    _ => todo!(),
                };

                let stack_pop_rhs = StackPop {
                    index: sp,
                    sub_index: SubIndex::default(),
                    value: rhs.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_lhs = StackPop {
                    index: sp - 1,
                    sub_index: SubIndex::default(),
                    value: lhs.into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp - 1,
                    sub_index: SubIndex::default(),
                    value: out.into(),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };

                match ty {
                    BinaryIntegerOperationType::Add
                    | BinaryIntegerOperationType::Sub
                    | BinaryIntegerOperationType::Lt
                    | BinaryIntegerOperationType::Gt
                    | BinaryIntegerOperationType::Le
                    | BinaryIntegerOperationType::Ge => {
                        let memory_ops = vec![
                            MemoryOp(Some(stack_pop_rhs), None, None),
                            MemoryOp(Some(stack_pop_lhs), Some(stack_push), None),
                        ];
                        vec![StageState {
                            step_states: vec![ExecStepState {
                                step_state,
                                memory_ops,
                            }],
                            extra_data: None,
                        }]
                    }
                    BinaryIntegerOperationType::BitAnd
                    | BinaryIntegerOperationType::BitOr
                    | BinaryIntegerOperationType::Xor => {
                        let memory_ops = vec![
                            MemoryOp(Some(stack_pop_rhs), None, None),
                            MemoryOp(Some(stack_pop_lhs), None, None),
                            MemoryOp(None, Some(stack_push), None),
                        ];
                        vec![StageState {
                            step_states: vec![ExecStepState {
                                step_state,
                                memory_ops,
                            }],
                            extra_data: None,
                        }]
                    }
                    _ => todo!(),
                }
            }
            Operation::Call { fh_idx, args } => {
                // TODO: for entrypoint, is there a call ?
                self.call_stack_versions.push(self.clk);
                // stage1: check the number of argument
                let mut step_state = StepState::new(self.clk, ExecutionState::CallStage1, trace)
                    .set_aux0(*fh_idx as u128);
                let mut stages = vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops: vec![MemoryOp(None, None, None)],
                    }],
                    extra_data: None,
                }];

                let callee_frame_index = current_frame_index + 1;
                for (i, arg) in args.iter().enumerate().rev() {
                    let local_index = args.len() - 1 - i;

                    // stage2: invalidate old local
                    self.clk += 1;
                    step_state = step_state
                        .change_state(ExecutionState::CallStage2)
                        .change_clk(self.clk);
                    let header_sub_index = SubIndex::default();
                    let header_slot = self.locals.peek_local_slot(
                        callee_frame_index,
                        local_index,
                        &header_sub_index,
                    );
                    let old_value_invalid = match header_slot {
                        None => true,
                        Some(s) => s.value_invalid,
                    };
                    let memory_ops = if old_value_invalid {
                        let (old_slot, new_slot) = self.locals.read_local_slot_with_clk(
                            callee_frame_index,
                            local_index,
                            &header_sub_index,
                            self.clk,
                        );
                        vec![MemoryOp(
                            None,
                            None,
                            Some(LocalReadWrite::new(
                                callee_frame_index.try_into().unwrap(),
                                local_index.try_into().unwrap(),
                                header_sub_index,
                                old_slot,
                                new_slot,
                            )),
                        )]
                    } else {
                        let old_local =
                            self.locals
                                .members(callee_frame_index, local_index, &header_sub_index);
                        if let Some(old_local) = old_local {
                            old_local
                                .iter()
                                .map(|(sub_index, slot)| {
                                    let (old_, new_) = self.locals.write_local_slot_with_clk(
                                        callee_frame_index,
                                        local_index,
                                        sub_index,
                                        slot.value.clone(),
                                        slot.value_header,
                                        true,
                                        self.clk,
                                    );
                                    LocalReadWrite::new(
                                        callee_frame_index.try_into().unwrap(),
                                        local_index.try_into().unwrap(),
                                        sub_index.clone(),
                                        old_,
                                        new_,
                                    )
                                })
                                .map(|local_op| MemoryOp(None, None, Some(local_op)))
                                .collect()
                        } else {
                            unreachable!()
                        }
                    };
                    let stage2_state = StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    };
                    stages.push(stage2_state);

                    //stage3: pop an argument and store into local of the next frame
                    self.clk += 1;
                    step_state = step_state
                        .change_state(ExecutionState::CallStage3)
                        .change_clk(self.clk);
                    let value_version = self.version_stack.pop().unwrap();
                    let memory_ops: Vec<_> = arg
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone().into(),
                                value: item.value.clone().into(),
                                value_header: item.header,
                                version: value_version,
                            };
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                callee_frame_index,
                                local_index,
                                &stack_pop.sub_index,
                                stack_pop.value.clone().into(),
                                stack_pop.value_header,
                                false,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                callee_frame_index.try_into().unwrap(),
                                local_index.try_into().unwrap(),
                                stack_pop.sub_index.clone(),
                                old_,
                                new_,
                            );
                            MemoryOp(Some(stack_pop), None, Some(local_op))
                        })
                        .collect();
                    let stage3_state = StageState {
                        step_states: vec![ExecStepState {
                            step_state,
                            memory_ops,
                        }],
                        extra_data: None,
                    };
                    stages.push(stage3_state);
                    step_state = step_state.dec_sp(1);
                }
                stages
            }
            Operation::Ret { caller } => {
                // TOOD: check the Ret at the top frame
                let frame_version = self.call_stack_versions.pop().unwrap_or_default();
                // stage1: check the number of argument
                let step_state = StepState::new(self.clk, ExecutionState::Ret, trace);

                let caller = caller.as_ref().map(|c| CallerData {
                    caller_frame_index: c.frame_index as u16,
                    caller_module_index: 0, // FIXME: module_id to module_index
                    caller_function_index: c.function_id as u16,
                    caller_pc: c.pc as u64, // TODO: check the type of pc
                });
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops: vec![MemoryOp::default()],
                    }],
                    extra_data: Some(
                        RetExtraAssignData {
                            frame_version,
                            caller,
                        }
                        .into(),
                    ),
                }]
            }
            _ => todo!(),
        }
    }
}

#[derive(Default)]
struct Locals {
    values: Vec<Vec<Local>>,
}

impl Locals {
    pub fn to_write_set(self) -> Vec<LocalReadWrite> {
        self.values
            .into_iter()
            .enumerate()
            .flat_map(|(frame_index, frame_local)| {
                frame_local
                    .into_iter()
                    .enumerate()
                    .flat_map(move |(local_index, l)| {
                        l.data.into_iter().map(move |(k, v)| {
                            LocalReadWrite::new(
                                frame_index as u16,
                                local_index as u16,
                                k,
                                v,
                                Slot::default(),
                            )
                        })
                    })
            })
            .collect()
    }
}

impl Locals {
    pub fn peek_local_slot(
        &mut self,
        frame_index: usize,
        local_index: usize,
        sub_index: &SubIndex,
    ) -> Option<&Slot> {
        self.values
            .get(frame_index)
            .and_then(|l| l.get(local_index))
            .and_then(|l| l.get(sub_index))
    }
    pub fn read_local_slot_with_clk(
        &mut self,
        frame_index: usize,
        local_index: usize,
        sub_index: &SubIndex,
        clk: u64,
    ) -> (Slot, Slot) {
        let new_slot = self
            .peek_local_slot(frame_index, local_index, sub_index)
            .cloned()
            .unwrap_or(Slot::default())
            .with_version(clk);
        let old_slot = self.write_slot(frame_index, local_index, sub_index, new_slot.clone());
        (old_slot, new_slot)
    }
    pub fn write_local_slot_with_clk(
        &mut self,
        frame_index: usize,
        local_index: usize,
        sub_index: &SubIndex,
        value: Word,
        is_header: bool,
        value_invalid: bool, // TODO: merge with value?
        clk: Version,
    ) -> (Slot, Slot) {
        let new_ = Slot {
            value,
            value_header: is_header,
            value_invalid,
            version: clk,
        };
        let old_ = self.write_slot(frame_index, local_index, sub_index, new_.clone());
        (old_, new_)
    }
    fn write_slot(
        &mut self,
        frame_index: usize,
        local_index: usize,
        sub_index: &SubIndex,
        new_: Slot,
    ) -> Slot {
        let slot = self
            .values
            .get_mut(frame_index)
            .and_then(|l| l.get_mut(local_index))
            .and_then(|l| l.get_mut(sub_index));
        match slot {
            None => {
                let old = Slot::default();

                if frame_index + 1 > self.values.len() {
                    self.values.resize_with(frame_index + 1, std::vec::Vec::new);
                }
                let locals = self.values.get_mut(frame_index).unwrap();
                if local_index + 1 > locals.len() {
                    locals.resize_with(local_index + 1, Local::default);
                }
                let local = locals.get_mut(local_index).unwrap();
                // insert the new slot to local
                local.data.insert(sub_index.clone(), new_.clone());
                old
            }
            Some(slot) => {
                let old = slot.clone();
                *slot = new_;
                old
            }
        }
    }

    /// Return member slots include itself
    pub fn members(
        &self,
        frame_index: usize,
        local_index: usize,
        sub_index: &SubIndex,
    ) -> Option<Vec<(SubIndex, Slot)>> {
        let local = self
            .values
            .get(frame_index)
            .and_then(|l| l.get(local_index));
        if let Some(local) = local {
            let members = local
                .deref()
                .iter()
                .map(|(si, slot)| (si.clone(), slot.clone()))
                .filter(|(si, slot)| {
                    si.to_trimmed_vec()
                        .starts_with(sub_index.to_trimmed_vec().as_slice())
                        && !slot.value_invalid
                })
                .collect::<Vec<_>>();
            Some(members)
        } else {
            None
        }
    }
}

/// each local is a map from sub_index to a value slot
#[derive(Default, Clone)]
struct Local {
    data: BTreeMap<SubIndex, Slot>,
}

impl Deref for Local {
    type Target = BTreeMap<SubIndex, Slot>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Local {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

///TODO: move to other place

pub mod to_u256 {
    use move_core_types::u256::U256;
    use move_vm_runtime::witnessing::traced_value::Integer;

    pub trait ToU256 {
        fn to_u256(&self) -> U256;
    }

    impl ToU256 for Integer {
        fn to_u256(&self) -> U256 {
            match self {
                Integer::U8(v) => U256::from(*v),
                Integer::U16(v) => U256::from(*v),
                Integer::U32(v) => U256::from(*v),
                Integer::U64(v) => U256::from(*v),
                Integer::U128(v) => U256::from(*v),
                Integer::U256(v) => *v,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use move_core_types::u256::U256;

    #[test]
    fn test_overflowing_sub() {
        let a = U256::from(0u8);
        let b = U256::max_value();
        let c = U256::from(1u8);
        assert_eq!(U256::wrapping_sub(a, b), c);

        let a = U256::from(0u8);
        let b = U256::from(1u8);
        let c = U256::max_value();
        assert_eq!(U256::wrapping_sub(a, b), c);
    }
}
