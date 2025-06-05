// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::{FixedTableTag, LookupTableConfigV2};
use crate::chips::execution_chip_v2::ExecChipConfig;
use crate::utils::challenges::Challenges;
use crate::utils::{SubCircuit, SubCircuitConfig};
use aptos_move_witnesses::static_info::{EntryInfo, Footprints, StaticInfo};
use aptos_move_witnesses::step_state::{ExecStepState, MemoryOp, StageState, StepState};
use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use move_binary_format::file_format_common::Opcodes;
use move_package::compilation::compiled_package::CompiledPackage;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use strum::IntoEnumIterator;
use types::Field;

// Thread-local storage to hold a reference-counted circuit instance.
// Allows circuits to be configured according to bytecode in the program.
thread_local! {
    static CIRCUIT_REF: RefCell<Option<Rc<VmCircuit<Fr>>>> = RefCell::new(None);
}

/// Registers a circuit instance in thread-local storage.
pub fn register_circuit(circuit: Rc<VmCircuit<Fr>>) {
    CIRCUIT_REF.with(|cell| {
        *cell.borrow_mut() = Some(circuit);
        #[cfg(debug_assertions)]
        eprintln!("Circuit registered in thread-local storage");
    });
}

/// Unregisters the circuit from thread-local storage, clearing the reference.
pub fn unregister_circuit() {
    CIRCUIT_REF.with(|cell| {
        *cell.borrow_mut() = None;
        #[cfg(debug_assertions)]
        eprintln!("Circuit unregistered from thread-local storage");
    });
}

/// Retrieves the currently registered circuit, if any.
pub fn get_circuit() -> Option<Rc<VmCircuit<Fr>>> {
    CIRCUIT_REF.with(|cell| cell.borrow().clone())
}

pub struct CircuitGuard {
    circuit: Rc<VmCircuit<Fr>>,
}

impl CircuitGuard {
    pub fn new(circuit: Rc<VmCircuit<Fr>>) -> Self {
        register_circuit(circuit.clone());
        Self { circuit }
    }
}

impl Drop for CircuitGuard {
    fn drop(&mut self) {
        unregister_circuit();
    }
}

#[derive(Clone)]
pub struct VmCircuitConfig<F: Field> {
    lookup_table_config: LookupTableConfigV2<F>,
    exec_chip_config: ExecChipConfig<F>,
    fixed_table_tags: Vec<FixedTableTag>,
}

pub struct VmCircuitConfigArgs {
    fixed_table_tags: Vec<FixedTableTag>,
    used_opcodes: Vec<Opcodes>,
}

impl<F: Field> SubCircuitConfig<F> for VmCircuitConfig<F> {
    type ConfigArgs = VmCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let lookup_table_config = LookupTableConfigV2::new(meta);
        let exec_chip_config =
            ExecChipConfig::configure(meta, &lookup_table_config, &args.used_opcodes);
        // TODO: delete me
        #[cfg(test)]
        {
            use crate::utils::cell_manager::CellType;
            let mut headers = CellType::all()
                .iter()
                .map(|t| format!("{:?}", t))
                .collect::<Vec<_>>();
            headers.insert(0, "state".to_string());
            println!("{}", headers.join(","));

            for (state, stat) in &exec_chip_config.dynamic_cell_stat_map {
                let mut stat = CellType::all()
                    .iter()
                    .map(|t| stat.get(t).cloned().unwrap_or_default().to_string())
                    .collect::<Vec<_>>();
                stat.insert(0, format!("{:?}", state));
                println!("{}", stat.join(","));
            }
        }

        Self {
            fixed_table_tags: args.fixed_table_tags,
            exec_chip_config,
            lookup_table_config,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitConfigV2 {
    pub max_rows: Option<usize>,
}

impl CircuitConfigV2 {
    pub fn new(max_rows: Option<usize>) -> Self {
        Self { max_rows }
    }
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub states: Vec<StageState>,
    pub static_info: StaticInfo,
    pub circuit_config: CircuitConfigV2,
    pub _maker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let circuit = get_circuit().expect(
            "VmCircuit not registered in thread-local storage; call register_circuit first",
        );
        let used_opcodes = circuit.static_info.used_opcodes();
        let fixed_table_tags = FixedTableTag::iter().collect();
        VmCircuitConfig::new(
            meta,
            VmCircuitConfigArgs {
                fixed_table_tags,
                used_opcodes,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.exec_chip_config.challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> SubCircuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;

    fn new(
        package: &CompiledPackage,
        traces: &Footprints,
        pubs_indices: &[usize],
        circuit_config: CircuitConfigV2,
    ) -> Self {
        let entry = traces.entry().expect("entry should be set in traces");
        let static_info = StaticInfo::generate(entry, package, pubs_indices)
            .expect("static info should be generated");
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.pre_process(&traces.0, &static_info);
        Self {
            states,
            static_info,
            circuit_config,
            _maker: Default::default(),
        }
    }
    fn new_with_empty_state(
        package: &CompiledPackage,
        entry: EntryInfo,
        pubs_indices: &[usize],
        circuit_config: CircuitConfigV2,
    ) -> Self {
        let num_rows = circuit_config
            .max_rows
            .expect("max_rows should be set in config");
        let static_info = StaticInfo::generate(entry, package, pubs_indices)
            .expect("static info should be generated");
        let empty_states = (0..num_rows).map(|_| StageState::default()).collect();
        Self {
            states: empty_states,
            static_info,
            circuit_config,
            _maker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        VmCircuitConfig {
            exec_chip_config,
            lookup_table_config,
            fixed_table_tags,
        }: &Self::Config,
        challenges: &Challenges<halo2_proofs::circuit::Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        //dbg!(&self.static_info.function_info);
        lookup_table_config.load(layouter, fixed_table_tags.clone(), &self.static_info)?;

        // Pads the states to match `max_rows` in the circuit config.
        let states = self.padding_states().unwrap_or_else(|| {
            panic!(
                "num of states rows {} exceeds the max num of rows",
                self.states.iter().map(|s| s.rows()).sum::<usize>()
            )
        });
        exec_chip_config.assign(layouter, states, &self.static_info, challenges)?;
        Ok(())
    }
}

impl<F: Field> VmCircuit<F> {
    /// Pads the states with default `StageState` to match `max_rows` in the circuit config.
    pub fn padding_states(&self) -> Option<Vec<StageState>> {
        if let Some(max_rows) = self.circuit_config.max_rows {
            let num_rows = self.states.iter().map(|s| s.rows()).sum::<usize>();
            if num_rows > max_rows {
                None
            } else {
                let mut padded_states = self.states.clone();
                if num_rows < max_rows {
                    let last_clk = padded_states
                        .last()
                        .and_then(|s| s.step_states.last())
                        .map(|state| state.step_state.clk)
                        .unwrap_or_default();

                    padded_states.extend((1..=(max_rows - num_rows)).map(|i| StageState {
                        step_states: vec![ExecStepState {
                            step_state: StepState::default().change_clk(last_clk + i as u64),
                            memory_ops: vec![MemoryOp(None, None, None)],
                        }],
                        extra_data: None,
                    }));
                }
                Some(padded_states)
            }
        } else {
            Some(self.states.clone())
        }
    }
    /// Return the minimum number of rows required to prove the circuit.
    pub fn circuit_height(&self) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = VmCircuit::<F>::configure(&mut cs);
        let table_rows = config
            .lookup_table_config
            .tables_height(&self.static_info, config.fixed_table_tags);

        let states_rows = if let Some(max_rows) = self.circuit_config.max_rows {
            max_rows
        } else {
            self.states.iter().map(|s| s.rows()).sum::<usize>()
        };

        let rows_needed = vec![table_rows, states_rows].into_iter().max().unwrap_or(0);

        // halo2 prover requires 'usable_rows = n - (blinding_factors + 1)'
        rows_needed + (cs.blinding_factors() + 1)
    }
}
