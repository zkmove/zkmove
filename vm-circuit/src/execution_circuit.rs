// Copyright (c) zkMove Authors

use crate::execution_circuit::executions::{ExecutionConfig, InstructionGadgetV2};
use crate::lookup_table::LookupTableConfigV2;
use crate::utils::vm_constraint_builder::VmConstraintBuilder;
use crate::{CircuitConfigArgs, SubCircuit, SubCircuitConfig};
use circuit_tool::challenges::Challenges;
use field_exts::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, ErrorFront as Error},
};
use move_binary_format::file_format_common::Opcodes;
use poseidon_base::Hashable;
use std::marker::PhantomData;
use witness::static_info::StaticInfo;
use witness::step_state::{ExecStepState, MemoryOp, StageState, StepState};

pub(crate) mod call_stack;
pub(crate) mod executions;
pub(crate) mod step;

/// Circuit of the MoveVM interpreter execution

#[derive(Clone, Default)]
pub(crate) struct ExecutionCircuitConfigArgs {
    pub(crate) used_opcodes: Vec<Opcodes>,
    pub(crate) use_poseidon_hash: bool,
}

#[derive(Clone)]
pub(crate) struct ExecutionCircuitConfig<F: Field> {
    pub(crate) execution_config: ExecutionConfig<F>,
    pub(crate) lookup_table_config: LookupTableConfigV2<F>,
}

impl<F: Field + Hashable> SubCircuitConfig<F> for ExecutionCircuitConfig<F> {
    type ConfigArgs = ExecutionCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let lookup_table_config = LookupTableConfigV2::new(meta, &args);
        let execution_config = ExecutionConfig::configure(
            meta,
            &lookup_table_config,
            &args.used_opcodes,
            args.use_poseidon_hash,
        );

        Self {
            execution_config,
            lookup_table_config,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct ExecutionCircuit<F: Field> {
    pub(crate) states: Vec<StageState>,
    pub(crate) static_info: StaticInfo,
    pub(crate) circuit_config_args: CircuitConfigArgs,
    phantom_: PhantomData<F>,
}

impl<F: Field + Hashable> SubCircuit<F> for ExecutionCircuit<F> {
    type Config = ExecutionCircuitConfig<F>;

    fn new(
        states: Vec<StageState>,
        static_info: StaticInfo,
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        Self {
            states,
            static_info,
            circuit_config_args,
            phantom_: PhantomData,
        }
    }

    fn new_with_empty_state(
        static_info: StaticInfo,
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        let num_rows = circuit_config_args
            .max_execution_rows
            .expect("max_execution_rows should be set in config");
        let empty_states = (0..num_rows).map(|_| StageState::default()).collect();
        Self {
            states: empty_states,
            static_info,
            circuit_config_args,
            phantom_: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        ExecutionCircuitConfig {
            execution_config,
            lookup_table_config,
        }: &Self::Config,
        challenges: &Challenges<halo2_proofs::circuit::Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        lookup_table_config.load(layouter, &self.static_info)?;

        // Pads the states to match `max_execution_rows` in the circuit config.
        let states = self.padding_states().unwrap_or_else(|| {
            panic!(
                "num of states rows {} exceeds the max num of rows",
                self.states.iter().map(|s| s.rows()).sum::<usize>()
            )
        });
        execution_config.assign(layouter, states, &self.static_info, challenges)?;

        Ok(())
    }
}

impl<F: Field> ExecutionCircuit<F> {
    /// Pads the states with default `StageState` to match `max_execution_rows` in the circuit config.
    pub fn padding_states(&self) -> Option<Vec<StageState>> {
        if let Some(max_execution_rows) = self.circuit_config_args.max_execution_rows {
            let num_rows = self.states.iter().map(|s| s.rows()).sum::<usize>();
            if num_rows > max_execution_rows {
                None
            } else {
                let mut padded_states = self.states.clone();
                if num_rows < max_execution_rows {
                    let last_clk = padded_states
                        .last()
                        .and_then(|s| s.step_states.last())
                        .map(|state| state.step_state.clk)
                        .unwrap_or_default();

                    padded_states.extend((1..=(max_execution_rows - num_rows)).map(|i| {
                        StageState {
                            step_states: vec![ExecStepState {
                                step_state: StepState::default().change_clk(last_clk + i as u64),
                                memory_ops: vec![MemoryOp(None, None, None)],
                            }],
                            extra_data: None,
                        }
                    }));
                }
                Some(padded_states)
            }
        } else {
            Some(self.states.clone())
        }
    }
}
