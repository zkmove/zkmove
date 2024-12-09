// Copyright (c) zkMove Authors

use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::{ExecStepState, MemoryOp, StageState, StepState};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitConfigV2 {
    pub max_num_rows: Option<usize>,
}

impl CircuitConfigV2 {
    pub fn new(max_num_rows: usize) -> Self {
        Self {
            max_num_rows: Some(max_num_rows),
        }
    }
}

#[derive(Clone, Default)]
pub struct WitnessV2 {
    pub opcode_witnesses: Vec<StageState>,
    pub static_info: StaticInfo,
    pub circuit_config: CircuitConfigV2,
}

impl WitnessV2 {
    pub fn new(
        opcode_witnesses: Vec<StageState>,
        static_info: StaticInfo,
        circuit_config: CircuitConfigV2,
    ) -> Self {
        WitnessV2 {
            opcode_witnesses,
            static_info,
            circuit_config,
        }
    }
    /// Pads the witness with default `StageState` to match `max_num_rows` in the circuit config.
    pub fn padding(&self) -> Option<WitnessV2> {
        if let Some(max_num_rows) = self.circuit_config.max_num_rows {
            let num_rows = self.num_rows();
            if num_rows > max_num_rows {
                None
            } else {
                let mut padded_witnesses = self.opcode_witnesses.clone();
                if num_rows < max_num_rows {
                    let last_clk = padded_witnesses
                        .last()
                        .and_then(|s| s.step_states.last())
                        .map(|state| state.step_state.clk)
                        .unwrap_or_default();

                    padded_witnesses.extend((1..=(max_num_rows - num_rows)).map(|i| StageState {
                        step_states: vec![ExecStepState {
                            step_state: StepState::default().change_clk(last_clk + i as u64),
                            memory_ops: vec![MemoryOp(None, None, None)],
                        }],
                        extra_data: None,
                    }));
                }
                Some(WitnessV2::new(
                    padded_witnesses,
                    self.static_info.clone(),
                    self.circuit_config.clone(),
                ))
            }
        } else {
            Some(self.clone())
        }
    }
    pub fn num_rows(&self) -> usize {
        self.opcode_witnesses.iter().map(|s| s.rows()).sum()
    }
}
