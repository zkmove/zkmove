// Copyright (c) zkMove Authors

#[cfg(not(feature = "test-circuits"))]
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::bn256::Fr;
#[cfg(not(feature = "test-circuits"))]
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::debug;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::Path;
#[cfg(feature = "test-circuits")]
use vm_circuit::mock_prove_circuit;
use vm_circuit::{
    best_k, CircuitConfigV2, Footprints, InstanceFields, SubCircuit, VmCircuit,
    NUM_INSTANCE_COLUMNS,
};
#[cfg(not(feature = "test-circuits"))]
use vm_circuit::{prove_circuit, setup_circuit, verify_circuit};

pub const TEST_PACKAGE_NAME: &str = "cases";
pub const TEST_CIRCUIT_ROWS: usize = 2000usize;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    debug!("Run test with trace {:?}", path.display());

    // load package
    let rooted_path = SourcePackageLayout::try_find_root(&path.canonicalize()?)?;
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(TEST_PACKAGE_NAME);
    let package =
        OnDiskCompiledPackage::from_path(build_path.as_path())?.into_compiled_package()?;

    // load traces
    let traces = Footprints::load(path)?;

    // For testing purposes, force all arguments to be public inputs.
    let args = traces.args().expect("Args not found");
    let pubs_indices: Vec<usize> = Vec::from_iter(0..args.len());
    let instances = InstanceFields::<_, NUM_INSTANCE_COLUMNS>::new(&args, pubs_indices.as_slice());

    #[cfg(feature = "test-circuits")]
    {
        debug!("Mock prove");
        let circuit =
            VmCircuit::<Fr>::new(&package, &traces, &pubs_indices, CircuitConfigV2::default());
        circuit.register();
        let k = best_k(&circuit);
        mock_prove_circuit(&circuit, instances.0, k)?;
    }

    #[cfg(not(feature = "test-circuits"))]
    {
        debug!("Generate keys with custom number of rows");
        let entry = traces.entry().expect("Entry not found");
        let config = CircuitConfigV2::new(Some(TEST_CIRCUIT_ROWS));
        let test_circuit =
            VmCircuit::<Fr>::new_with_empty_state(&package, entry, &pubs_indices, config.clone());
        test_circuit.register();
        let k = best_k(&test_circuit);
        debug!("k = {}", k);
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let params = ParamsKZG::<Bn256>::setup(k, rng);
        let (vk, pk) = setup_circuit(&test_circuit, &params)?;
        test_circuit.unregister();

        debug!("Generate zk proof");
        let circuit = VmCircuit::<Fr>::new(&package, &traces, &pubs_indices, config);
        circuit.register();
        let proof = prove_circuit(circuit, &instances.as_ref(), &params, &pk)
            .expect("proof generation should not fail");
        verify_circuit(&instances.as_ref(), &params, &vk, &proof)
            .expect("verify proof should be ok");
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "witnesses", r".*\.json");
