// Copyright (c) zkMove Authors

//! Sui transaction-payload builders, decoupled from CLI argument parsing and file IO.
//!
//! Each function returns a `serde_json::Value` payload; serialization/saving is left to
//! the command layer.

use crate::common::KZGVariant;
use crate::ops::circuit::build_circuit_and_fit_params;
use anyhow::Result;
use halo2::proofs::{setup_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::kzg::commitment::ParamsKZG,
};
use move_package::compilation::compiled_package::CompiledPackage;
use sui_verifier_api::native_verifier::{
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
use sui_verifier_api::SuiMoveCallJSON;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::Footprints;

/// Build the payload publishing the KZG params to the Sui native verifier.
pub fn build_publish_params_native(
    params: &ParamsKZG<Bn256>,
    verifier_api_package: &str,
    params_store_object_id: &str,
) -> Result<SuiMoveCallJSON> {
    build_publish_params_native_transaction_payload(
        params,
        verifier_api_package,
        params_store_object_id,
    )
}

/// Build the payload publishing the circuit's verifying key to the Sui native verifier.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn build_publish_circuit_native(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    verifier_api_package: &str,
) -> Result<SuiMoveCallJSON> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params);

    let (vk, _pk) = setup_circuit(&*circuit, params)
        .map_err(|e| anyhow::anyhow!("Failed to setup circuit: {:?}", e))?;

    build_publish_vk_native_transaction_payload(&vk, params, circuit.as_ref(), verifier_api_package)
}

/// Build the payload verifying a proof on the Sui native verifier.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_proof_native(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    verifier_api_package: &str,
    params_object_id: &str,
    vk_object_id: &str,
    k: Option<u32>,
) -> Result<SuiMoveCallJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_native_transaction_payload::<G1Affine>(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        verifier_api_package,
        params_object_id,
        vk_object_id,
        k,
    )
}
