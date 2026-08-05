use crate::static_info::StaticInfo;
use crate::Footprint;
use move_core_types::u256::U256;

mod execution_state;
mod memory_op;
pub use execution_state::ExecutionState;
pub use memory_op::{LocalReadWrite, MemoryOp, Slot, StackPop, StackPush};

pub type Version = u64;

#[derive(Clone, Debug)]
pub struct StageState {
    pub step_states: Vec<ExecStepState>,
    pub extra_data: Option<StageExtraAssignData>,
}
impl Default for StageState {
    fn default() -> Self {
        Self {
            step_states: vec![ExecStepState::default()],
            extra_data: None,
        }
    }
}
impl StageState {
    pub fn rows(&self) -> usize {
        self.step_states.iter().map(|s| s.memory_ops.len()).sum()
    }
}

#[derive(Clone, Debug)]
pub enum StageExtraAssignData {
    Ret(RetExtraAssignData),
    Start(EntryFunc),
    ProcessArg(ProcessArgData),
    BinaryOp(BinaryOpData),
}

#[derive(Clone, Debug)]
pub struct ProcessArgData {
    pub public_input_rows: Vec<Option<usize>>,
}

impl From<ProcessArgData> for StageExtraAssignData {
    fn from(value: ProcessArgData) -> Self {
        Self::ProcessArg(value)
    }
}

#[derive(Clone, Debug)]
pub struct BinaryOpData {
    pub lhs: U256,
    pub rhs: U256,
    pub out: U256,
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
    pub caller_module_index: u32,
    pub caller_function_index: u16,
    pub caller_pc: u16,
}

#[derive(Clone, Debug)]
pub struct EntryFunc {
    pub module_index: u32,
    pub function_index: u16,
}

impl From<EntryFunc> for StageExtraAssignData {
    fn from(entry: EntryFunc) -> Self {
        Self::Start(entry)
    }
}

#[derive(Clone, Debug)]
pub struct ExecStepState {
    pub step_state: StepState,
    pub memory_ops: Vec<MemoryOp>,
}
impl Default for ExecStepState {
    fn default() -> Self {
        Self {
            step_state: StepState::default(),
            memory_ops: vec![MemoryOp::default()],
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct StepState {
    pub clk: Version,
    pub frame_index: u16,
    pub module_index: u32,
    pub function_index: u16,
    pub pc: u16,
    pub sp: u16,
    pub opcode: u8,
    pub operand0: u128,
    pub operand1: u128,
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
            opcode: 0, // have to set opcode == 0 for teardown, or else bytecode lookup cannot pass.
            operand0: 0,
            operand1: 0,
            exec_state: ExecutionState::Stop,
        }
    }
}

impl StepState {
    pub fn new(
        clk: Version,
        state: ExecutionState,
        trace: &Footprint,
        static_info: &StaticInfo,
    ) -> Self {
        let module_index = static_info
            .module_id_mapping
            .get_module_index(trace.module_id.as_ref().unwrap());
        let bytecode = static_info
            .get_bytecode(module_index, trace.function_id as u16, trace.pc as usize)
            .unwrap_or_else(|| {
                panic!(
                    "cannot locate the bytecode, {},{},{}",
                    module_index, trace.function_id, trace.pc
                )
            });
        Self {
            clk,
            frame_index: trace.frame_index as u16,
            module_index,
            function_index: trace.function_id as u16,
            pc: trace.pc,
            sp: trace.stack_pointer as u16,
            opcode: bytecode.opcode,
            operand0: bytecode.operand0.unwrap_or_default(),
            operand1: bytecode.operand1.unwrap_or_default(),
            exec_state: state,
        }
    }
    pub fn inc_sp(mut self, delta: u16) -> Self {
        self.sp += delta;
        self
    }
    pub fn dec_sp(mut self, delta: u16) -> Self {
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
    pub fn set_operand0(mut self, value: u128) -> Self {
        self.operand0 = value;
        self
    }
    pub fn set_operand1(mut self, value: u128) -> Self {
        self.operand1 = value;
        self
    }
}
