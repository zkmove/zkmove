// Copyright (c) zkMove Authors

// use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::bn256::Fr;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::Path;

use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use aptos_move_witnesses::Footprint;
use log::debug;
use vm_circuit::circuit_v2::VmCircuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{mock_prove_circuit, SubCircuit};
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
    let module_id = traces.first().unwrap().module_id.clone().unwrap();
    let function_index = traces.first().unwrap().function_id;
    let static_info = StaticInfo::generate(&module_id, function_index, &package);
    let preprocessor = WitnessPreProcessor::default();
    let states = preprocessor.pre_process(&traces, &static_info);
    println!("states={:#?}", states);

    let witness = WitnessV2::new(states, static_info, CircuitConfigV2::default());
    let circuit = VmCircuit::<Fr>::new_from_witness(&witness);

    let k = 18; //TODO: auto pick best k
    mock_prove_circuit(&circuit, vec![], k)?;

    // TODO: gen key, prove, verify
    Ok(())
}

datatest_stable::harness!(vm_test, "witnesses", r".*\.json");
