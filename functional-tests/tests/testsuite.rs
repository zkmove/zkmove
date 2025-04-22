// Copyright (c) zkMove Authors

use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use aptos_move_witnesses::{Footprint, Operation};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::debug;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::Path;
use vm_circuit::chips::execution_chip_v2::instance::public_inputs_to_fields;
use vm_circuit::circuit_v2::VmCircuit;
#[cfg(feature = "test-circuits")]
use vm_circuit::mock_prove_circuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{best_k, prove_and_verify_kzg, setup_circuit, SubCircuit};

pub const TEST_PACKAGE_NAME: &str = "cases";
pub const TEST_CIRCUIT_ROWS: usize = 2000usize;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    // let source_file = path.to_str().expect("path is None.");
    debug!("Run test with trace {:?}", path.display());

    // Always root ourselves to the package root, and then compile relative to that.
    let rooted_path = SourcePackageLayout::try_find_root(&path.canonicalize()?)?;
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(TEST_PACKAGE_NAME);
    let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
    let package = package.into_compiled_package()?;
    let trace_contents = std::fs::read_to_string(path)?;
    let traces: Vec<Footprint> = serde_json::from_str(&trace_contents)?;
    let (num_arg, entry) = match &traces.first().unwrap().data {
        Operation::Start { entry_call } => (entry_call.args.len(), entry_call),
        _ => unreachable!(),
    };
    // For testing purposes, force all arguments to be public inputs.
    let public_inputs: Vec<usize> = Vec::from_iter(0..num_arg);

    let static_info = StaticInfo::generate(
        entry.module_id.as_ref().unwrap(),
        entry.function_index as u16,
        &package,
        public_inputs.as_slice(),
    );
    let preprocessor = WitnessPreProcessor::default();
    let states = preprocessor.pre_process(&traces, &static_info);
    let witness = WitnessV2::new(
        states.clone(),
        static_info.clone(),
        CircuitConfigV2::default(),
    );
    let circuit = VmCircuit::<Fr>::new_from_witness(&witness);

    let instances: Vec<Vec<Fr>> = public_inputs_to_fields(&entry.args, public_inputs.as_slice());
    #[cfg(feature = "test-circuits")]
    {
        debug!("Mock prove");
        let k = best_k(&circuit);
        mock_prove_circuit(&circuit, instances, k)?;
    }

    #[cfg(not(feature = "test-circuits"))]
    {
        debug!("Generate keys with custom number of state rows");
        let circuit_config = CircuitConfigV2::new(TEST_CIRCUIT_ROWS);
        let empty_states = (0..TEST_CIRCUIT_ROWS)
            .map(|_| StageState::default())
            .collect();
        let empty_witness =
            WitnessV2::new(empty_states, static_info.clone(), circuit_config.clone());
        let empty_circuit = VmCircuit::<Fr>::new_from_witness(&empty_witness);
        let k = best_k(&empty_circuit);
        debug!("k = {}", k);
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let params = ParamsKZG::<Bn256>::setup(k, rng);
        let (_, pk) = setup_circuit(&circuit, &params)?;

        debug!("Generate zk proof");
        let witness = WitnessV2::new(states, static_info, circuit_config);
        let circuit = VmCircuit::<Fr>::new_from_witness(&witness);
        // Convert to &[&[F]]
        let slices: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();
        let instances_ref: &[&[Fr]] = &slices;
        prove_and_verify_kzg(circuit, instances_ref, &params, pk.clone());
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "witnesses", r".*\.json");
