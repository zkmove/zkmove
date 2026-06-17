// Copyright (c) zkMove Authors

//! On-chain (native) verifier test-data generation, decoupled from CLI/IO.

use crate::common::KZGVariant;
use crate::ops::circuit::build_circuit_and_fit_params;
use anyhow::{Context, Result};
use halo2::proofs::setup_circuit;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use halo2_verifier::{test_verifier, KZG as VerifierKZG};
use move_package::compilation::compiled_package::CompiledPackage;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::Footprints;

/// Serialized inputs the native (on-chain) verifier consumes.
pub struct TestVerifierOutput {
    pub serialized_params: Vec<u8>,
    pub vk_bytes: Vec<u8>,
    pub circuit_info_bytes: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs_bytes: Vec<u8>,
}

/// Run the native verifier against a freshly generated proof and return its serialized inputs.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn test_native_verifier(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    params: &mut ParamsKZG<Bn256>,
    pubs_indices: &[usize],
    variant: KZGVariant,
) -> Result<TestVerifierOutput> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params);

    let args = traces.args().context("Arguments not found in witness")?;
    let public_inputs = PublicInputs::new(&args, pubs_indices);

    let (_vk, _pk) = setup_circuit(&*circuit, params).expect("setup should not fail");

    let verifier_kzg_scheme = match variant {
        KZGVariant::GWC => VerifierKZG::GWC,
        KZGVariant::SHPLONK => VerifierKZG::SHPLONK,
    };

    let test_data = test_verifier(
        circuit.as_ref().clone(),
        public_inputs.as_vec(),
        params,
        verifier_kzg_scheme,
    )
    .expect("on-chain verifier test should not fail");

    Ok(TestVerifierOutput {
        serialized_params: test_data.serialized_params,
        vk_bytes: test_data.vk_bytes,
        circuit_info_bytes: test_data.circuit_info_bytes,
        proof: test_data.proof,
        public_inputs_bytes: test_data.public_inputs_bytes,
    })
}
