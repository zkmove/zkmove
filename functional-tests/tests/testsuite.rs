// Copyright (c) zkMove Authors

use halo2::proofs::best_k;
#[cfg(feature = "test-circuits")]
use halo2::proofs::mock_prove_circuit;
#[cfg(not(feature = "test-circuits"))]
use halo2::proofs::{prove_circuit, setup_circuit, verify_circuit, KZG};
#[cfg(not(feature = "test-circuits"))]
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::bn256::Fr;
#[cfg(not(feature = "test-circuits"))]
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use log::debug;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::Path;
use std::rc::Rc;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use witness::static_info::Footprints;

pub const TEST_PACKAGE_NAME: &str = "cases";
pub const TEST_CIRCUIT_ROWS: usize = 2000usize;
pub const TEST_HASH_ROWS: usize = 100usize;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
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
    // The public inputs are the arguments at odd indices.
    let pubs_indices: Vec<usize> = (0..args.len()).filter(|index| index % 2 == 1).collect();
    let public_inputs = PublicInputs::new(&args, pubs_indices.as_slice());
    let circuit_config_args = CircuitConfigArgs::new(Some(TEST_CIRCUIT_ROWS), TEST_HASH_ROWS);
    #[cfg(feature = "test-circuits")]
    {
        debug!("Mock prove");
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &pubs_indices,
            circuit_config_args.clone(),
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());
        let k = best_k(&circuit);
        mock_prove_circuit(&*circuit, &public_inputs, k).expect("mock prove should not fail");
    }

    #[cfg(not(feature = "test-circuits"))]
    {
        debug!("Generate keys with custom number of rows");
        let entry = traces.entry().expect("Entry not found");
        let (params, vk, pk) = {
            let test_circuit = Rc::new(VmCircuit::<Fr>::new_with_empty_state(
                &package,
                entry,
                &pubs_indices,
                circuit_config_args.clone(),
            ));
            let _circuit_guard = CircuitGuard::new(test_circuit.clone());
            let k = best_k(&test_circuit);
            debug!("k = {}", k);
            let rng = rand::rngs::mock::StepRng::new(0, 1);
            let params = ParamsKZG::<Bn256>::setup(k, rng);
            let (vk, pk) = setup_circuit(&*test_circuit, &params).expect("setup should not fail");
            (params, vk, pk)
        };

        debug!("Generate zk proof");
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &pubs_indices,
            circuit_config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());
        let proof = prove_circuit((*circuit).clone(), &public_inputs, &params, &pk, KZG::GWC)
            .expect("proof generation should not fail");
        verify_circuit(&public_inputs, &params, &vk, &proof, KZG::GWC)
            .expect("verify proof should be ok");
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "witnesses", r".*\.json");
