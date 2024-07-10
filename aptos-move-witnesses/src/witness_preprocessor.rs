use crate::exec_state::ExecutionState;
use crate::step_state::{
    ExecStepState, LocalReadWrite, MemoryOp, Slot, StackPop, StackPush, StepState, SubIndex,
    Version,
};
use move_vm_runtime::witnessing::traced_value::{Reference, SimpleValue};
use move_vm_runtime::witnessing::{Footprint, Operation};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

pub struct WitnessPreProcessor {
    clk: Version,
    // track versions of each stack value
    version_stack: Vec<Version>,
    locals: Locals,
}
impl WitnessPreProcessor {
    pub fn pre_process(mut self, traces: &Vec<crate::Footprint>) -> Vec<ExecStepState> {
        let mut exec_states = vec![];
        for footprint in traces {
            let mut states = self.process_footprint(footprint);
            exec_states.append(&mut states);
            self.clk += 1;
        }
        exec_states
    }

    fn process_footprint(&mut self, trace: &Footprint) -> Vec<ExecStepState> {
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
                vec![stage1_state, stage2_state]
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
                vec![ExecStepState {
                    step_state,
                    memory_ops,
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
                vec![ExecStepState {
                    step_state,
                    memory_ops,
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

                vec![ExecStepState {
                    step_state: StepState::new(self.clk, ExecutionState::VecLen, trace),
                    memory_ops: vec![MemoryOp(Some(stack_pop), Some(stack_push), Some(local_op))],
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
                vec![ExecStepState {
                    step_state: StepState::new(self.clk, exec_state, trace),
                    memory_ops: vec![MemoryOp(None, Some(stack_push), None)],
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
                sub_index.push((*field_offset + 1) as usize);
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
                vec![ExecStepState {
                    step_state: StepState::new(self.clk, exec_state, trace),
                    memory_ops: vec![MemoryOp(Some(stack_pop), Some(stack_push), None)],
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
                vec![ExecStepState {
                    step_state: StepState::new(self.clk, exec_state, trace),
                    memory_ops: vec![
                        MemoryOp(Some(stack_pop_idx), None, None),
                        MemoryOp(Some(stack_pop_vec_ref), Some(stack_push), None),
                    ],
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
