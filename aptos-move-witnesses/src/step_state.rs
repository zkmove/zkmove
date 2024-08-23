use crate::exec_state::ExecutionState;
use crate::types::sub_index::SubIndex;
use crate::types::word::Word;
use crate::Footprint;

pub type Version = u64;

#[derive(Clone, Debug)]
pub struct StageState {
    pub step_states: Vec<ExecStepState>,
    pub extra_data: Option<StageExtraAssignData>,
}

impl StageState {
    pub fn rows(&self) -> usize {
        self.step_states.iter().map(|s| s.memory_ops.len()).sum()
    }
}

#[derive(Clone, Debug)]
pub enum StageExtraAssignData {
    Ret(RetExtraAssignData),
}

#[derive(Clone, Debug)]
pub struct RetExtraAssignData {
    pub caller: Option<CallerData>,
    pub frame_version: Version,
}

impl From<RetExtraAssignData> for StageExtraAssignData {
    fn from(value: RetExtraAssignData) -> Self {
        Self::Ret(value)
    }
}
#[derive(Clone, Debug)]
pub struct CallerData {
    pub caller_frame_index: u16,
    pub caller_module_index: u64, // TODO: module_id to module_index
    pub caller_function_index: u16,
    pub caller_pc: u64,
}

#[derive(Clone, Debug)]
pub struct ExecStepState {
    pub step_state: StepState,
    pub memory_ops: Vec<MemoryOp>,
}

#[derive(Clone, Copy, Debug)]
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

impl Default for StepState {
    fn default() -> Self {
        Self {
            clk: 0,
            frame_index: 0,
            module_index: 0,
            function_index: 0,
            pc: 0,
            sp: 0,
            opcode: 0,
            aux0: 0,
            aux1: 0,
            exec_state: ExecutionState::Nop,
        }
    }
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
    pub fn set_aux0(mut self, value: u128) -> Self {
        self.aux0 = value;
        self
    }
    pub fn set_aux1(mut self, value: u128) -> Self {
        self.aux1 = value;
        self
    }
}

#[derive(Default, Clone, Debug)]
pub struct MemoryOp(
    pub Option<StackPop>,
    pub Option<StackPush>,
    pub Option<LocalReadWrite>,
);

#[derive(Clone, Debug)]
pub struct StackPop {
    pub index: u64,
    pub sub_index: SubIndex,
    pub value: Word,
    pub value_header: bool,
    pub version: u64,
}
#[derive(Clone, Debug)]
pub struct StackPush {
    pub index: u64,
    pub sub_index: SubIndex,
    pub value: Word,
    pub value_header: bool,
    pub version: u64,
}
#[derive(Clone, Debug)]
pub struct LocalReadWrite {
    pub frame_index: u16, // TODO: types of frame_index and local_index
    pub index: u16,
    pub sub_index: SubIndex,
    pub read_value: Word,
    pub read_value_header: bool,
    pub read_value_invalid: bool,
    pub read_version: u64,
    pub write_value: Word,
    pub write_value_header: bool,
    pub write_value_invalid: bool,
    pub write_version: u64,
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

#[derive(Clone, Debug)]
pub struct Slot {
    pub value: Word,
    pub value_header: bool,
    pub value_invalid: bool,
    pub version: u64,
}

/// every slot's default value
impl Default for Slot {
    fn default() -> Self {
        Self {
            value: Word::default(),
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
