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
    pub(crate) needs_sub_index: bool,
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
            args.needs_sub_index,
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

    fn circuit_height(&self, config: &Self::Config) -> usize {
        let table_rows = config.lookup_table_config.tables_height(&self.static_info);

        let states_rows =
            if let Some(max_execution_rows) = self.circuit_config_args.max_execution_rows {
                max_execution_rows
            } else {
                self.states.iter().map(|s| s.rows()).sum::<usize>()
            };

        table_rows.max(states_rows)
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

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::ConstraintSystem;
    use move_binary_format::file_format_common::Opcodes;

    fn configure(needs_sub_index: bool) -> ConstraintSystem<Fr> {
        let mut cs = ConstraintSystem::<Fr>::default();
        let args = ExecutionCircuitConfigArgs {
            used_opcodes: vec![Opcodes::RET],
            use_poseidon_hash: false,
            needs_sub_index,
        };
        let _ = <ExecutionCircuitConfig<Fr> as SubCircuitConfig<Fr>>::new(&mut cs, args);
        cs
    }

    /// The compact layout must be exactly the full layout minus the sub_index
    /// dimension: three step cells and the eight bytes of the teardown address
    /// key that carry `sub_index`.  This is a layout regression test; update the
    /// numbers when the circuit layout intentionally changes.
    #[test]
    fn compact_layout_omits_sub_index_cells() {
        let full = configure(true);
        let compact = configure(false);

        assert_eq!(full.num_advice_columns(), 76);
        assert_eq!(compact.num_advice_columns(), 65);
        assert_eq!(full.lookups().len(), 29);
        assert_eq!(compact.lookups().len(), 21);

        // Only cells disappear; gates and their polynomials are unchanged.
        assert_eq!(full.gates().len(), compact.gates().len());
        assert_eq!(
            full.gates()
                .iter()
                .map(|g| g.polynomials().len())
                .sum::<usize>(),
            compact
                .gates()
                .iter()
                .map(|g| g.polynomials().len())
                .sum::<usize>()
        );
    }
}
