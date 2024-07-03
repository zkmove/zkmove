use crate::exec_state::ExecutionState;
use crate::{Footprint, Operation};
use move_vm_runtime::witnessing::traced_value::SimpleValue;
use std::collections::BTreeMap;
use std::ops::Deref;

pub struct ExecStepState {
    pub step_state: StepState,
    pub memory_ops: Vec<MemoryOp>,
}
pub struct StepState {
    pub clk: u64,
    pub frame_index: u16,
    pub module_index: u64, // TODO: module_id to module_index
    pub function_index: u16,
    pub pc: u64,
    pub sp: u64,
    pub opcode: u16,
    pub aux0: u128,
    pub aux1: u128,
    pub exec_state: ExecutionState,
}
impl StepState {
    pub fn new(clk: u64, state: ExecutionState, trace: &Footprint) -> Self {
        Self {
            clk,
            frame_index: trace.frame_index as u16,
            module_index: 0, // FIXME
            function_index: trace.function_id as u16,
            pc: trace.pc as u64,
            sp: trace.stack_pointer as u64,
            opcode: trace.op as u16, //FIXME
            aux0: 0,                 // FIXME
            aux1: 0,                 // FIXME
            exec_state: state,
        }
    }
    pub fn inc_sp(mut self, delta: u64) -> Self {
        self.sp += delta;
        self
    }
    pub fn dec_sp(mut self, delta: u64) -> Self {
        self.sp -= delta;
        self
    }
    pub fn change_state(mut self, state: ExecutionState) -> Self {
        self.exec_state = state;
        self
    }
    pub fn change_clk(mut self, clk: Version) -> Self {
        self.clk = clk;
        self
    }
}

impl ExecStepState {}
#[derive(Default, Clone, Debug)]
pub struct MemoryOp(
    pub Option<StackPop>,
    pub Option<StackPush>,
    pub Option<LocalReadWrite>,
);

#[derive(Clone, Debug)]
pub struct StackPop {
    index: u64,
    sub_index: SubIndex, // TODO change to u256
    value: SimpleValue,
    value_header: bool,
    version: u64,
}
#[derive(Clone, Debug)]
pub struct StackPush {
    index: u64,
    sub_index: SubIndex, // TODO change to u256
    value: SimpleValue,
    value_header: bool,
    version: u64,
}
#[derive(Clone, Debug)]
pub struct LocalReadWrite {
    frame_index: u16, // TODO: types of frame_index and local_index
    index: u16,
    sub_index: SubIndex,
    read_value: SimpleValue,
    read_value_header: bool,
    read_value_invalid: bool,
    read_version: u64,
    write_value: SimpleValue,
    write_value_header: bool,
    write_value_invalid: bool,
    write_version: u64,
}

impl LocalReadWrite {
    pub fn new(
        frame_index: u16,
        local_index: u16,
        sub_index: SubIndex,
        old_slot: Slot,
        new_slot: Slot,
    ) -> Self {
        LocalReadWrite {
            frame_index,
            index: local_index,
            sub_index,
            read_value: old_slot.value,
            read_value_header: old_slot.value_header,
            read_value_invalid: old_slot.value_invalid,
            read_version: old_slot.version,
            write_value: new_slot.value,
            write_value_header: new_slot.value_header,
            write_value_invalid: new_slot.value_invalid,
            write_version: new_slot.version,
        }
    }
}

pub type Version = u64;
struct WitnessPreProcessor {
    clk: Version,
    // track versions of each stack value
    version_stack: Vec<Version>,
    locals: Locals,
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
            .get(frame_index as usize)
            .and_then(|l| l.get(local_index as usize))
            .and_then(|l| l.get(&sub_index))
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
            .get_mut(frame_index as usize)
            .and_then(|l| l.get_mut(local_index))
            .and_then(|l| l.get_mut(&sub_index));
        match slot {
            None => {
                let old = Slot::default();

                if frame_index + 1 > self.values.len() {
                    self.values.resize_with(frame_index + 1, || vec![]);
                }
                let locals = self.values.get_mut(frame_index).unwrap();
                if local_index + 1 > locals.len() {
                    locals.resize_with(local_index + 1, || Local::default());
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
pub type SubIndex = Vec<usize>;

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

#[derive(Clone, Debug)]
struct Slot {
    value: SimpleValue,
    value_header: bool,
    value_invalid: bool,
    version: u64,
}

/// every slot's default value
impl Default for Slot {
    fn default() -> Self {
        Self {
            value: SimpleValue::U8(0), // TODO: change this
            value_header: false,
            value_invalid: true,
            version: 0,
        }
    }
}

impl Slot {
    pub fn with_version(mut self, version: Version) -> Self {
        debug_assert!(version > self.version);
        self.version = version;
        self
    }
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
                let step_state = StepState::new(self.clk, ExecutionState::StoreLocStage1, &trace);
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
                        step_state: step_state.clone(),
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
                            *local_index as u16,
                            stack_pop.sub_index.clone(),
                            stack_pop.value.clone(),
                            stack_pop.value_header,
                            false,
                            self.clk,
                        );
                        let local_op = LocalReadWrite::new(
                            current_frame_index,
                            *local_index,
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
            Operation::VecLen { si, vec_ref, len } => {
                let stack_pop = StackPop {
                    index: sp as u64,
                    sub_index: vec![0],
                    value: SimpleValue::Reference(vec_ref.clone()),
                    value_header: false,
                    version: self.version_stack.pop().unwrap(),
                };
                self.version_stack.push(self.clk);
                let stack_push = StackPush {
                    index: sp as u64,
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

                self.clk += 1;

                vec![ExecStepState {
                    step_state: StepState::new(self.clk, ExecutionState::VecLen, trace),
                    memory_ops: vec![MemoryOp(Some(stack_pop), Some(stack_push), Some(local_op))],
                }]
            }
            _ => unimplemented!(),
        }
    }
}
