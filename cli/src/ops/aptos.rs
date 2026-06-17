// Copyright (c) zkMove Authors

//! Aptos transaction-payload builders, decoupled from CLI argument parsing and file IO.
//!
//! Each function returns an `EntryFunctionArgumentsJSON` payload; serialization/saving is
//! left to the command layer.

use crate::common::KZGVariant;
use crate::ops::circuit::build_circuit_and_fit_params;
use anyhow::Result;
use aptos_verifier_api::native_verifier::{
    build_publish_circuit_native_transaction_payload,
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
use aptos_verifier_api::verifier::{
    build_publish_circuit_transaction_payload, build_publish_params_transaction_payload,
    build_verify_proof_transaction_payload,
};
use aptos_verifier_api::EntryFunctionArgumentsJSON;
use halo2::proofs::{setup_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::kzg::commitment::ParamsKZG,
};
use move_package::compilation::compiled_package::CompiledPackage;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::Footprints;

/// The two payloads produced when publishing a circuit to the Aptos native verifier.
pub struct NativeCircuitTxns {
    /// Payload publishing the verifying key.
    pub vk: EntryFunctionArgumentsJSON,
    /// Payload publishing the circuit/params.
    pub circuit: EntryFunctionArgumentsJSON,
}

/// Build the payload publishing the KZG params to the Aptos (move) verifier.
pub fn build_publish_params(
    params: &ParamsKZG<Bn256>,
    params_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    build_publish_params_transaction_payload(params, params_contract_address)
}

/// Build the payload publishing the circuit to the Aptos (move) verifier.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn build_publish_circuit(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    verifier_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params);

    build_publish_circuit_transaction_payload(params, circuit.as_ref(), verifier_contract_address)
}

/// Build the payload verifying a proof on the Aptos (move) verifier.
pub fn build_verify_proof(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    verifier_contract_address: &str,
    verifier_address: &str,
    params_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_transaction_payload(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        verifier_contract_address,
        verifier_address,
        params_address,
    )
}

/// Build the payload publishing the KZG params to the Aptos native verifier.
pub fn build_publish_params_native(
    params: &ParamsKZG<Bn256>,
    params_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    build_publish_params_native_transaction_payload(params, params_contract_address.to_string())
}

/// Build the vk + circuit payloads publishing a circuit to the Aptos native verifier.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn build_publish_circuit_native(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    native_verifier_contract_address: &str,
) -> Result<NativeCircuitTxns> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params);

    let (vk, _pk) = setup_circuit(&*circuit, params)
        .map_err(|e| anyhow::anyhow!("Failed to setup circuit: {:?}", e))?;

    let vk_txn = build_publish_vk_native_transaction_payload(
        &vk,
        native_verifier_contract_address.to_string(),
    )?;
    let circuit_txn = build_publish_circuit_native_transaction_payload(
        params,
        circuit.as_ref(),
        native_verifier_contract_address.to_string(),
    )?;

    Ok(NativeCircuitTxns {
        vk: vk_txn,
        circuit: circuit_txn,
    })
}

/// Build the payload verifying a proof on the Aptos native verifier.
#[allow(clippy::too_many_arguments)]
pub fn build_verify_proof_native(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    native_verifier_contract_address: &str,
    native_verifier_address: &str,
    params_address: &str,
    k: Option<u32>,
) -> Result<EntryFunctionArgumentsJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_native_transaction_payload::<G1Affine>(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        native_verifier_contract_address,
        native_verifier_address,
        params_address,
        k,
    )
}
