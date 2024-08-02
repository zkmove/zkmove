use crate::exec_state::ExecutionState;
use crate::exec_state::ExecutionState::{
    VecSwapStage2, VecSwapStage3, VecSwapStage4, VecSwapStage5,
};
use crate::step_state::{
    ExecStepState, LocalReadWrite, MemoryOp, Slot, StackPop, StackPush, StageState, StepState,
    SubIndex, Version,
};
use crate::sub_index;
use crate::utils::{SubIndexUtils, ValueHeader};
use crate::witness_preprocessor::to_u256::ToU256;
use move_core_types::u256::U256;
use move_vm_runtime::witnessing::traced_value::{Integer, Reference, SimpleValue, ValueItem};
use move_vm_runtime::witnessing::{BinaryIntegerOperationType, Footprint, Operation};
use move_vm_types::values::IntegerValue;
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

pub struct WitnessPreProcessor {
    clk: Version,
    // track versions of each stack value
    version_stack: Vec<Version>,
    locals: Locals,
}
impl WitnessPreProcessor {
    pub fn pre_process(mut self, traces: &Vec<crate::Footprint>) -> Vec<StageState> {
        let mut exec_states = vec![];
        for footprint in traces {
            let mut states = self.process_footprint(footprint);
            exec_states.append(&mut states);
            self.clk += 1;
        }
        exec_states
    }

    fn process_footprint(&mut self, trace: &Footprint) -> Vec<StageState> {
        let sp = trace.stack_pointer as u64;
        let current_frame_index = trace.frame_index;
        match &trace.data {
            Operation::StLoc {
                local_index,
                old_local,
                new_value,
            } => {
                // stage1 of st_loc.
                let step_state = StepState::new(self.clk, ExecutionState::StoreLocStage1, trace);
                let stage1_state = {
                    let header_check_sub_index = vec![0];

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
                                        &item.sub_index,
                                        item.value.clone(),
                                        item.header,
                                        true,
                                        self.clk,
                                    );
                                    LocalReadWrite::new(
                                        current_frame_index as u16,
                                        *local_index as u16,
                                        item.sub_index.clone(),
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
                            sub_index: value_item.sub_index.clone(),
                            value: value_item.value.clone(),
                            value_header: value_item.header,
                            version: value_version,
                        };
                        let (old_, new_) = self.locals.write_local_slot_with_clk(
                            current_frame_index,
                            *local_index as u16 as usize,
                            &stack_pop.sub_index,
                            stack_pop.value.clone(),
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
                    },
                    StageState {
                        step_states: vec![stage2_state],
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
                            &item.sub_index,
                            item.value.clone(),
                            item.header,
                            true,
                            self.clk,
                        );
                        // TODO: check old_ == local[sub_index]
                        let stack_push = StackPush {
                            index: step_state.sp + 1,
                            sub_index: item.sub_index.clone(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            current_frame_index as u16,
                            *local_index as u16,
                            item.sub_index.clone(),
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
                            &item.sub_index,
                            self.clk,
                        );
                        // TODO: check old_ == local[sub_index]
                        let stack_push = StackPush {
                            index: step_state.sp + 1,
                            sub_index: item.sub_index.clone(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            current_frame_index as u16,
                            *local_index as u16,
                            item.sub_index.clone(),
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
                }]
            }
            Operation::VecLen { si, vec_ref, len } => {
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(vec_ref.clone()),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::U64(*len),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let (old_slot, new_slot) = self.locals.read_local_slot_with_clk(
                    vec_ref.frame_index,
                    vec_ref.local_index,
                    &vec_ref.sub_index,
                    self.clk,
                );
                let local_op = LocalReadWrite::new(
                    vec_ref.frame_index as u16,
                    vec_ref.local_index as u16,
                    vec_ref.sub_index.clone(),
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
                }]
            }
            Operation::BorrowLoc { imm, local_index } => {
                let exec_state = if *imm {
                    ExecutionState::ImmBorrowLoc
                } else {
                    ExecutionState::MutBorrowLoc
                };
                let loc_ref = Reference {
                    frame_index: current_frame_index,
                    local_index: *local_index as usize,
                    sub_index: vec![0],
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp + 1,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(loc_ref),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, exec_state, trace),
                        memory_ops: vec![MemoryOp(None, Some(stack_push), None)],
                    }],
                }]
            }
            Operation::BorrowField {
                imm,
                fh_idx,
                reference,
                field_offset,
            } => {
                let exec_state = if *imm {
                    ExecutionState::ImmBorrowField
                } else {
                    ExecutionState::MutBorrowField
                };
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(reference.clone()),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let mut sub_index = reference.sub_index.clone();
                sub_index.push(*field_offset + 1);
                let field_ref = Reference {
                    frame_index: reference.frame_index,
                    local_index: reference.local_index,
                    sub_index,
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(field_ref),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state: StepState::new(self.clk, exec_state, trace),
                        memory_ops: vec![MemoryOp(Some(stack_pop), Some(stack_push), None)],
                    }],
                }]
            }
            Operation::VecBorrow {
                si,
                imm,
                idx,
                vec_ref,
            } => {
                let exec_state = if *imm {
                    ExecutionState::VecImmBorrow
                } else {
                    ExecutionState::VecMutBorrow
                };
                let stack_pop_idx = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::U64(*idx),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_vec_ref = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(vec_ref.clone()),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let mut sub_index = vec_ref.sub_index.clone();
                sub_index.push((*idx + 1) as usize);
                let element_ref = Reference {
                    frame_index: vec_ref.frame_index,
                    local_index: vec_ref.local_index,
                    sub_index,
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(element_ref),
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
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

                    let _ = memory_ops.last_mut().unwrap().1.insert(StackPush {
                        index: step_state.sp,
                        sub_index: vec![0],
                        value: SimpleValue::Bool(if matches!(&trace.data, Operation::Eq { .. }) {
                            lhs_sorted == rhs_sorted
                        } else {
                            lhs_sorted != rhs_sorted
                        }),
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
                    },
                    StageState {
                        step_states: vec![stage2_state],
                    },
                ]
            }
            Operation::ReadRef { reference, value } => {
                let step_state = StepState::new(self.clk, ExecutionState::ReadRef, trace);
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(reference.clone()),
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
                            &item.sub_index,
                            self.clk,
                        );
                        let stack_push = StackPush {
                            index: sp,
                            sub_index: item.sub_index.clone(),
                            value: old_.value.clone(),
                            value_header: old_.value_header,
                            version: self.clk,
                        };
                        let local_op = LocalReadWrite::new(
                            reference.frame_index.try_into().unwrap(),
                            reference.local_index.try_into().unwrap(),
                            item.sub_index.clone(),
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
                        sub_index: vec![0],
                        value: SimpleValue::Reference(reference.clone()),
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
                                &item.sub_index,
                                item.value.clone(),
                                item.header,
                                true,
                                self.clk,
                            );
                            let local_op = LocalReadWrite::new(
                                reference.frame_index.try_into().unwrap(),
                                reference.local_index.try_into().unwrap(),
                                item.sub_index.clone(),
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
                                value_header: item.header,
                                version: value_version,
                            };
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                reference.frame_index,
                                reference.local_index,
                                &stack_pop.sub_index,
                                stack_pop.value.clone(),
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
                    let depth = reference.sub_index.depth();
                    let parents = reference.sub_index.parents().unwrap();
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

                            let new_parent_value: SimpleValue =
                                ValueHeader::new(flen as u16, len).into();
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                reference.frame_index,
                                reference.local_index,
                                sub_index,
                                new_parent_value,
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
                    },
                    StageState {
                        step_states: vec![stage2_state],
                    },
                    StageState {
                        step_states: vec![stage3_state],
                    },
                ]
            }
            Operation::Pack { sd_idx, args } => {
                let step_state = StepState::new(self.clk, ExecutionState::Pack, trace);

                let flen = args.iter().fold(0usize, |sum, arg| sum + arg.len()) + 1;
                let len = args.len() as u64;

                let mut memory_ops = vec![MemoryOp(
                    None,
                    Some(StackPush {
                        index: step_state.sp + 1 - len,
                        sub_index: vec![0],
                        value: SimpleValue::U128((len as u128) << (64 + flen)), // TODO: check on this
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
                            sub_index: item.sub_index.clone(),
                            value: item.value.clone(),
                            value_header: item.header,
                            version,
                        };
                        let stack_push = StackPush {
                            index: step_state.sp + 1 - len,
                            sub_index: {
                                let mut sub_index = item.sub_index.clone();
                                sub_index.insert(0, i + 1);
                                sub_index
                            },
                            value: item.value.clone(),
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
                }]
            }
            Operation::Unpack { sd_idx, arg } => {
                debug_assert!(!arg.is_empty());
                let step_state = StepState::new(self.clk, ExecutionState::UnpackStage1, trace);
                let arg_header = arg.first().unwrap();
                let arg_version = self.version_stack.pop().unwrap();
                let stack_pop = StackPop {
                    index: step_state.sp,
                    sub_index: arg_header.sub_index.clone(),
                    value: arg_header.value.clone(),
                    value_header: arg_header.header,
                    version: arg_version,
                };
                let mut stages = vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops: vec![MemoryOp(Some(stack_pop), None, None)],
                    }],
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
                    fields.keys().cloned().collect::<Vec<_>>(),
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
                                    sub_index: item.sub_index.clone(),
                                    value: item.value.clone(),
                                    value_header: item.header,
                                    version: arg_version,
                                };
                                let stack_push = StackPush {
                                    index: step_state.sp + field_index as u64 - 1,
                                    sub_index: {
                                        let mut sub_index = item.sub_index.clone();
                                        sub_index.remove(0); // drop the field_index
                                        sub_index.push(0); // in case sub_index only have 1 elem.
                                        sub_index
                                    },
                                    value: item.value.clone(),
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
                                    sub_index: vec![0],
                                    value,
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
                    let idx_items_sub_index_prefix =
                        sub_index::concat(vec_ref.sub_index.clone(), vec![*idx as usize]);
                    let memory_ops = idx_elem
                        .iter()
                        .map(|item| {
                            let item_sub_index = sub_index::concat(
                                idx_items_sub_index_prefix.clone(),
                                item.sub_index.clone(),
                            );
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &item_sub_index,
                                item.value.clone(),
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
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
                    let idx_items_sub_index_prefix =
                        sub_index::concat(vec_ref.sub_index.clone(), vec![*idx as usize]);
                    let stack_value_version = self.version_stack.pop().unwrap();
                    let memory_ops = idx_elem
                        .iter()
                        .map(|item| {
                            let stack_pop = StackPop {
                                index: step_state.sp,
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
                                value_header: item.header,
                                version: stack_value_version,
                            };
                            let item_sub_index = sub_index::concat(
                                idx_items_sub_index_prefix.clone(),
                                item.sub_index.clone(),
                            );
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &item_sub_index,
                                item.value.clone(),
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
                        sub_index: vec![0],
                        value: SimpleValue::Reference(vec_ref.clone()),
                        value_header: false,
                        version: self.version_stack.pop().unwrap(),
                    };
                    let mut memory_ops = vec![];

                    let mut parents = vec_ref.sub_index.parents().unwrap_or_default();
                    // insert itself
                    parents.insert(0, vec_ref.sub_index.clone());
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
                            parent_header.flen - elem.len() as u16,
                            if i == 0 {
                                parent_header.len - 1
                            } else {
                                parent_header.len
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
                    }
                };

                self.clk += 1;

                let stage2 = {
                    self.version_stack.push(self.clk);
                    let step_state = step_state.change_state(ExecutionState::VecPopBackStage2);

                    let memory_ops = elem
                        .iter()
                        .map(|item| {
                            let local_item_sub_index = sub_index::concat(
                                vec_ref.sub_index.clone(),
                                sub_index::concat(vec![*vec_len as usize], item.sub_index.clone()),
                            );
                            // invalidate local slot
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &local_item_sub_index,
                                item.value.clone(),
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
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
                        sub_index: vec![0],
                        value: SimpleValue::Reference(vec_ref.clone()),
                        value_header: false,
                        version: self.version_stack.pop().unwrap(),
                    };
                    let mut memory_ops = vec![];

                    let mut parents = vec_ref.sub_index.parents().unwrap_or_default();
                    // insert itself
                    parents.insert(0, vec_ref.sub_index.clone());
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
                            parent_header.flen + elem.len() as u16,
                            if i == 0 {
                                parent_header.len + 1
                            } else {
                                parent_header.len
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
                                sub_index: item.sub_index.clone(),
                                value: item.value.clone(),
                                value_header: item.header,
                                version,
                            };
                            let local_item_sub_index = sub_index::concat(
                                vec_ref.sub_index.clone(),
                                sub_index::concat(
                                    vec![*vec_len as usize + 1],
                                    item.sub_index.clone(),
                                ),
                            );
                            // invalidate local slot
                            let (old_, new_) = self.locals.write_local_slot_with_clk(
                                vec_ref.frame_index,
                                vec_ref.local_index,
                                &local_item_sub_index,
                                item.value.clone(),
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
                    sub_index: vec![0],
                    value: SimpleValue::Bool(*rhs),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_lhs = StackPop {
                    index: sp - 1,
                    sub_index: vec![0],
                    value: SimpleValue::Bool(*lhs),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp - 1,
                    sub_index: vec![0],
                    value: SimpleValue::Bool(out),
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
                }]
            }
            Operation::Not { value } => {
                let step_state = StepState::new(self.clk, ExecutionState::Not, trace);
                let stack_pop = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Bool(*value),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp,
                    sub_index: vec![0],
                    value: SimpleValue::Bool(!(*value)),
                    value_header: false,
                    version: *self.version_stack.last().unwrap(),
                };
                let memory_ops = vec![MemoryOp(Some(stack_pop), Some(stack_push), None)];
                vec![StageState {
                    step_states: vec![ExecStepState {
                        step_state,
                        memory_ops,
                    }],
                }]
            }
            Operation::BinaryOp { ty, rhs, lhs } => {
                let num_bytes = match (lhs, rhs) {
                    (Integer::U8(l), Integer::U8(r)) => 1usize,
                    (Integer::U16(l), Integer::U16(r)) => 2usize,
                    (Integer::U32(l), Integer::U32(r)) => 4usize,
                    (Integer::U64(l), Integer::U64(r)) => 8usize,
                    (Integer::U128(l), Integer::U128(r)) => 16usize,
                    (Integer::U256(l), Integer::U256(r)) => 32usize,
                    _ => unreachable!(),
                };

                let (out, step_state) = match ty {
                    // while calculating the result, wrapping around at the boundary of the u256,
                    // to prevent overflow from stopping the computing.
                    BinaryIntegerOperationType::Add => {
                        let output = U256::wrapping_add(lhs.to_u256(), rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::AddSub, trace)
                            .set_aux0(num_bytes as u128);
                        (SimpleValue::U256(output), step_state)
                    }
                    BinaryIntegerOperationType::Sub => {
                        let output = U256::wrapping_sub(lhs.to_u256(), rhs.to_u256());
                        let step_state = StepState::new(self.clk, ExecutionState::AddSub, trace)
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
                    _ => todo!(),
                };

                let stack_pop_rhs = StackPop {
                    index: sp,
                    sub_index: vec![0],
                    value: rhs.clone().into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                let stack_pop_lhs = StackPop {
                    index: sp - 1,
                    sub_index: vec![0],
                    value: lhs.clone().into(),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp - 1,
                    sub_index: vec![0],
                    value: out,
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
                }]
            }
            _ => unimplemented!(),
        }
    }
}

struct Locals {
    values: Vec<Vec<Local>>,
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
        value: SimpleValue,
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
                .filter(|(si, slot)| si.starts_with(sub_index.as_slice()) && !slot.value_invalid)
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
