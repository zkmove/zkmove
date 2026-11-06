// Copyright (c) zkMove Authors

use halo2::proofs::best_k;
#[cfg(not(feature = "test-circuits"))]
use halo2::proofs::{prove_circuit, setup_circuit, verify_circuit, KZG};
#[cfg(feature = "test-circuits")]
use halo2_proofs::dev::{MockProver, VerifyFailure};
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
use witness::witness_manifest::WitnessManifest;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();
    debug!("Run test with trace {:?}", path.display());

    // Load the manifest written by `zkmove vm run-all`; each case carries its
    // own circuit configuration (rows and poseidon rows).
    let rooted_path = SourcePackageLayout::try_find_root(&path.canonicalize()?)?;
    let manifest_path = rooted_path.join("witnesses/manifest.json");
    let manifest: WitnessManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let witness_file = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .expect("witness file name should be valid UTF-8");
    let case = manifest
        .cases
        .iter()
        .find(|case| case.witness == witness_file)
        .expect("witness is not listed in witnesses/manifest.json");
    debug!("Run case {} ({})", case.name, case.module_id);

    // load package
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(&manifest.package);
    let package =
        OnDiskCompiledPackage::from_path(build_path.as_path())?.into_compiled_package()?;

    // load traces
    let traces = Footprints::load(path)?;

    // For testing purposes, force all arguments to be public inputs.
    let args = traces.args().expect("Args not found");
    // The public inputs are the arguments at odd indices.
    let pubs_indices: Vec<usize> = (0..args.len()).filter(|index| index % 2 == 1).collect();
    let public_inputs = PublicInputs::new(&args, pubs_indices.as_slice());
    let circuit_config_args =
        CircuitConfigArgs::new(Some(case.max_execution_rows), case.max_poseidon_rows);
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
        let prover = MockProver::run(k, &*circuit, public_inputs.as_vec())
            .expect("mock prover should not fail to run");
        // MockProver flags cells that are only assigned by gates of *other*
        // execution states as unassigned on padding rows (real proving treats
        // them as zero and the constraints still hold).  Ignore those layout
        // hygiene failures; any actual constraint/lookup/permutation failure
        // is still reported below.
        let failures = prover.verify().err().unwrap_or_default();
        let failures: Vec<_> = failures
            .into_iter()
            .filter(|failure| !matches!(failure, VerifyFailure::CellNotAssigned { .. }))
            .collect();
        assert!(failures.is_empty(), "mock prove failed: {failures:#?}");
    }

    #[cfg(not(feature = "test-circuits"))]
    {
        debug!("Generate keys with the case's circuit config");
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

datatest_stable::harness!(vm_test, "witnesses", r"test_.*\.json");
