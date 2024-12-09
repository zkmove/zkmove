// Copyright (c) zkMove Authors

// use functional_tests::run_config::RunConfig;
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
use vm_circuit::circuit_v2::VmCircuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{mock_prove_circuit, prove_and_verify_kzg, setup_circuit, SubCircuit};
pub const TEST_PACKAGE_NAME: &str = "cases";

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
    let entry = match &traces.first().unwrap().data {
        Operation::Start { entry_call } => entry_call,
        _ => unreachable!(),
    };
    let static_info = StaticInfo::generate(
        entry.module_id.as_ref().unwrap(),
        entry.function_index as u16,
        &package,
    );
    let preprocessor = WitnessPreProcessor::default();
    let states = preprocessor.pre_process(&traces, &static_info);

    let k = 12; //TODO: auto pick best k
    debug!("Mock prove");
    let witness = WitnessV2::new(
        states.clone(),
        static_info.clone(),
        CircuitConfigV2::default(),
    );
    let circuit = VmCircuit::<Fr>::new_from_witness(&witness);
    mock_prove_circuit(&circuit, vec![], k)?;

    debug!("Generate parameters");
    let rng = rand::rngs::mock::StepRng::new(0, 1);
    let params = ParamsKZG::<Bn256>::setup(k, rng);

    debug!("Generate keys with custom number of state rows");
    let max_num_rows = 3000usize;
    let circuit_config = CircuitConfigV2::new(max_num_rows);
    let empty_states = (0..max_num_rows).map(|_| StageState::default()).collect();
    let witness = WitnessV2::new(empty_states, static_info.clone(), circuit_config.clone());
    let circuit = VmCircuit::<Fr>::new_from_witness(&witness);
    let (_, pk) = setup_circuit(&circuit, &params)?;

    debug!("Generate zk proof");
    let witness = WitnessV2::new(states, static_info, circuit_config);
    let circuit = VmCircuit::<Fr>::new_from_witness(&witness);
    prove_and_verify_kzg(circuit, &[], &params, pk.clone());

    Ok(())
}

datatest_stable::harness!(vm_test, "witnesses", r".*\.json");
