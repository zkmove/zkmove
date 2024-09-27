// Copyright (c) zkMove Authors

use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitConfigV2 {
    pub max_steps: Option<usize>,
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
}
