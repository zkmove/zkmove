use crate::exec_state::ExecutionState;
use crate::Footprint;
use move_vm_runtime::witnessing::traced_value::SimpleValue;

pub type SubIndex = Vec<usize>;

pub type Version = u64;

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

#[derive(Default, Clone, Debug)]
pub struct MemoryOp(
    pub Option<StackPop>,
    pub Option<StackPush>,
    pub Option<LocalReadWrite>,
);

#[derive(Clone, Debug)]
pub struct StackPop {
    pub index: u64,
    pub sub_index: SubIndex, // TODO change to u256, or change to [u64]
    pub value: SimpleValue,
    pub value_header: bool,
    pub version: u64,
}
#[derive(Clone, Debug)]
pub struct StackPush {
    pub index: u64,
    pub sub_index: SubIndex, // TODO change to u256
    pub value: SimpleValue,
    pub value_header: bool,
    pub version: u64,
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

#[derive(Clone, Debug)]
pub struct Slot {
    pub value: SimpleValue,
    pub value_header: bool,
    pub value_invalid: bool,
    pub version: u64,
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
