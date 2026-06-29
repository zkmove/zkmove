// Copyright (c) zkMove Authors
#![allow(non_camel_case_types)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::wrong_self_convention)]
#![allow(dead_code)]

use crate::execution_circuit::{
    ExecutionCircuit, ExecutionCircuitConfig, ExecutionCircuitConfigArgs,
};
use crate::poseidon_circuit::{PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs};
use circuit_tool::challenges::Challenges;
use field_exts::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::ErrorFront;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, ErrorFront as Error},
};
use move_package::compilation::compiled_package::CompiledPackage;
use poseidon_base::Hashable;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use witness::preprocessor::WitnessPreProcessor;
use witness::static_info::{EntryInfo, Footprints, StaticInfo};
use witness::step_state::StageState;

pub(crate) mod execution_circuit;
pub(crate) mod gadgets;
pub(crate) mod lookup_table;
pub(crate) mod poseidon_circuit;
pub(crate) mod utils;

pub mod public_inputs;

// Thread-local storage to hold a reference-counted circuit instance.
// Allows circuits to be configured according to bytecode in the program.
thread_local! {
    static CIRCUIT_REF: RefCell<Option<Rc<VmCircuit<Fr>>>> = const { RefCell::new(None) };
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CircuitConfigArgs {
    pub max_execution_rows: Option<usize>,
    pub max_poseidon_rows: usize,
}

impl CircuitConfigArgs {
    pub fn new(max_execution_rows: Option<usize>, max_poseidon_rows: usize) -> Self {
        Self {
            max_execution_rows,
            max_poseidon_rows,
        }
    }
}

#[derive(Clone)]
pub struct VmCircuitConfig<F: Field> {
    pub(crate) execution_circuit_config: ExecutionCircuitConfig<F>,
    pub(crate) poseidon_circuit_config: Option<PoseidonCircuitConfig<F>>,
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub(crate) circuit_config_args: CircuitConfigArgs,
    /// Execution SubCircuit
    pub(crate) execution_circuit: ExecutionCircuit<F>,
    /// Poseidon hash SubCircuit
    pub(crate) poseidon_circuit: Option<PoseidonCircuit<F>>,
    _maker: PhantomData<F>,
}

impl<F: Field + Hashable> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let circuit = get_circuit().expect(
            "VmCircuit not registered in thread-local storage; call register_circuit first",
        );

        let used_opcodes = circuit.execution_circuit.static_info.used_opcodes();
        let use_poseidon_hash = circuit.poseidon_circuit.is_some();
        let execution_circuit_config_args = ExecutionCircuitConfigArgs {
            used_opcodes,
            use_poseidon_hash,
        };

        let execution_circuit_config =
            ExecutionCircuitConfig::new(meta, execution_circuit_config_args);
        let poseidon_circuit_config = if use_poseidon_hash {
            let poseidon_circuit_config_args = PoseidonCircuitConfigArgs {
                poseidon_table: execution_circuit_config
                    .lookup_table_config
                    .poseidon_table
                    .expect("Poseidon table should be present"),
            };
            Some(PoseidonCircuitConfig::new(
                meta,
                poseidon_circuit_config_args,
            ))
        } else {
            None
        };

        VmCircuitConfig {
            execution_circuit_config,
            poseidon_circuit_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config
            .execution_circuit_config
            .execution_config
            .challenges
            .values(&layouter);
        self.execution_circuit.synthesize_sub(
            &config.execution_circuit_config,
            &challenges,
            &mut layouter,
        )?;
        if let Some(poseidon_circuit) = &self.poseidon_circuit {
            let poseidon_circuit_config = config
                .poseidon_circuit_config
                .as_ref()
                .expect("Poseidon circuit config should be present");
            poseidon_circuit.synthesize_sub(poseidon_circuit_config, &challenges, &mut layouter)?;
        }
        Ok(())
    }
}

impl<F: Field + Hashable> VmCircuit<F> {
    /// Creates a new `VmCircuit` with the given compiled package, execution trace and public input indices
    pub fn new(
        package: &CompiledPackage,
        traces: &Footprints,
        pubs_indices: &[usize],
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        Self::try_new(package, traces, pubs_indices, circuit_config_args)
            .expect("VmCircuit should be constructed from witness")
    }

    /// Fallible constructor used by SDK/CLI paths so user input errors do not panic.
    pub fn try_new(
        package: &CompiledPackage,
        traces: &Footprints,
        pubs_indices: &[usize],
        circuit_config_args: CircuitConfigArgs,
    ) -> Result<Self, String> {
        let entry = traces
            .entry()
            .ok_or_else(|| "entry should be set in traces".to_string())?;
        let static_info = Self::static_info(package, &entry, pubs_indices)?;
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.process(&traces.0, &static_info);
        let execution_circuit = ExecutionCircuit::new(
            states.clone(),
            static_info.clone(),
            circuit_config_args.clone(),
        );
        let poseidon_circuit = if static_info.contain_zkhash() {
            Some(PoseidonCircuit::new(
                states,
                static_info,
                circuit_config_args.clone(),
            ))
        } else {
            None
        };

        let circuit = Self {
            circuit_config_args,
            execution_circuit,
            poseidon_circuit,
            _maker: Default::default(),
        };
        circuit.validate_capacity()?;
        Ok(circuit)
    }

    /// Creates a new `VmCircuit` with empty states, useful for circuit setup or testing.
    pub fn new_with_empty_state(
        package: &CompiledPackage,
        entry: EntryInfo,
        pubs_indices: &[usize],
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        Self::try_new_with_empty_state(package, entry, pubs_indices, circuit_config_args)
            .expect("VmCircuit should be constructed from empty state")
    }

    /// Fallible empty-state constructor used by setup/context loading paths.
    pub fn try_new_with_empty_state(
        package: &CompiledPackage,
        entry: EntryInfo,
        pubs_indices: &[usize],
        circuit_config_args: CircuitConfigArgs,
    ) -> Result<Self, String> {
        let static_info = Self::static_info(package, &entry, pubs_indices)?;
        Self::validate_empty_state_config(&static_info, &circuit_config_args)?;
        let execution_circuit = ExecutionCircuit::new_with_empty_state(
            static_info.clone(),
            circuit_config_args.clone(),
        );
        let poseidon_circuit = if static_info.contain_zkhash() {
            Some(PoseidonCircuit::new_with_empty_state(
                static_info,
                circuit_config_args.clone(),
            ))
        } else {
            None
        };
        let circuit = Self {
            circuit_config_args,
            execution_circuit,
            poseidon_circuit,
            _maker: Default::default(),
        };
        circuit.validate_capacity()?;
        Ok(circuit)
    }

    /// Return the minimum number of rows required to prove the circuit.
    pub fn circuit_height(&self) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = VmCircuit::<F>::configure(&mut cs);

        let execution_circuit_rows = self
            .execution_circuit
            .circuit_height(&config.execution_circuit_config);

        let poseidon_circuit_rows = if let Some(poseidon_circuit) = self.poseidon_circuit.as_ref() {
            poseidon_circuit.circuit_height(
                config
                    .poseidon_circuit_config
                    .as_ref()
                    .expect("Poseidon circuit config should be present"),
            )
        } else {
            0
        };

        let rows_needed = std::cmp::max(execution_circuit_rows, poseidon_circuit_rows);
        // halo2 prover requires 'usable_rows = n - (blinding_factors + 1)'
        rows_needed + (cs.blinding_factors() + 1)
    }

    /// Validate that the witness data fits the configured circuit capacities.
    pub fn validate_capacity(&self) -> Result<(), String> {
        if let Some(max_execution_rows) = self.circuit_config_args.max_execution_rows {
            let execution_rows = self.execution_rows();
            if execution_rows > max_execution_rows {
                return Err(format!(
                    "execution rows {} exceed configured max_execution_rows {}",
                    execution_rows, max_execution_rows
                ));
            }
        }

        if let Some(poseidon_circuit) = self.poseidon_circuit.as_ref() {
            poseidon_circuit.validate_capacity()?;
        }

        Ok(())
    }

    /// Validate setup inputs before constructing an empty-state circuit.
    pub fn validate_setup_inputs(
        package: &CompiledPackage,
        entry_info: &EntryInfo,
        pubs_indices: &[usize],
        circuit_config_args: &CircuitConfigArgs,
    ) -> Result<(), String> {
        let static_info = Self::static_info(package, entry_info, pubs_indices)?;
        Self::validate_empty_state_config(&static_info, circuit_config_args)
    }

    fn execution_rows(&self) -> usize {
        self.execution_circuit
            .states
            .iter()
            .map(StageState::rows)
            .sum()
    }

    fn static_info(
        package: &CompiledPackage,
        entry_info: &EntryInfo,
        pubs_indices: &[usize],
    ) -> Result<StaticInfo, String> {
        Self::validate_public_input_indices(entry_info, pubs_indices)?;
        StaticInfo::generate(entry_info.clone(), package, pubs_indices)
            .ok_or_else(|| format!("static info should be generated for entry {:?}", entry_info))
    }

    fn validate_public_input_indices(
        entry_info: &EntryInfo,
        pubs_indices: &[usize],
    ) -> Result<(), String> {
        let num_args = entry_info.num_args as usize;
        let mut seen = Vec::with_capacity(pubs_indices.len());
        for &index in pubs_indices {
            if index >= num_args {
                return Err(format!(
                    "public input index {} is out of bounds for entry with {} args",
                    index, num_args
                ));
            }
            if seen.contains(&index) {
                return Err(format!(
                    "public input index {} appears more than once",
                    index
                ));
            }
            seen.push(index);
        }
        Ok(())
    }

    fn validate_empty_state_config(
        static_info: &StaticInfo,
        circuit_config_args: &CircuitConfigArgs,
    ) -> Result<(), String> {
        if circuit_config_args.max_execution_rows.is_none() {
            return Err("max_execution_rows is required when building setup artifacts".to_string());
        }

        if static_info.contain_zkhash() {
            let hash_block_size = F::hash_block_size();
            let max_hashes = circuit_config_args.max_poseidon_rows / hash_block_size;
            if max_hashes == 0 {
                return Err(format!(
                    "max_poseidon_rows {} cannot fit one Poseidon hash block of {} rows",
                    circuit_config_args.max_poseidon_rows, hash_block_size
                ));
            }
        }

        Ok(())
    }
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full move verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
#[allow(clippy::too_long_first_doc_paragraph)]
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        256
    }

    /// Create a new SubCircuit
    fn new(
        states: Vec<StageState>,
        static_info: StaticInfo,
        circuit_config_args: CircuitConfigArgs,
    ) -> Self;
    /// Create a new SubCircuit with empty state
    fn new_with_empty_state(
        static_info: StaticInfo,
        circuit_config_args: CircuitConfigArgs,
    ) -> Self;
    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), ErrorFront>;
    /// Return the minimum number of rows required to prove the SubCircuit.
    fn circuit_height(&self, config: &Self::Config) -> usize;
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;

    #[test]
    fn validate_capacity_rejects_execution_rows_above_limit() {
        let config = CircuitConfigArgs::new(Some(1), 0);
        let execution_circuit = <ExecutionCircuit<Fr> as SubCircuit<Fr>>::new(
            vec![StageState::default(), StageState::default()],
            StaticInfo::default(),
            config.clone(),
        );
        let circuit = VmCircuit::<Fr> {
            circuit_config_args: config,
            execution_circuit,
            poseidon_circuit: None,
            _maker: Default::default(),
        };

        let err = circuit.validate_capacity().unwrap_err();
        assert!(err.contains("execution rows 2 exceed configured max_execution_rows 1"));
    }
}
