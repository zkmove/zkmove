// Copyright (c) zkMove Authors

//! Proof generation logic, decoupled from CLI argument parsing and file IO.

use crate::common::KZGVariant;
use crate::ops::circuit::build_circuit_and_fit_params;
use anyhow::{Context, Result};
use halo2::proofs::{prove_circuit, setup_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use move_package::compilation::compiled_package::CompiledPackage;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::Footprints;

/// The artifacts produced by [`prove`].
pub struct ProveOutput {
    /// The serialized proof bytes.
    pub proof: Vec<u8>,
    /// The serialized public inputs (instance) bytes.
    pub instance: Vec<u8>,
    /// The serialized verifying key (`SerdeFormat::Processed`).
    pub vk: Vec<u8>,
    /// The optimal `k` (degree) the proof was generated with.
    pub k: u32,
    /// The public inputs, retained so callers can render them in other formats.
    pub public_inputs: PublicInputs<Fr>,
}

/// Generate a proof for the given witness against the circuit derived from `package`.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn prove(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    params: &mut ParamsKZG<Bn256>,
    pubs_indices: &[usize],
    variant: KZGVariant,
) -> Result<ProveOutput> {
    let (circuit, _circuit_guard, k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params);

    let args = traces.args().context("Arguments not found in witness")?;
    let public_inputs = PublicInputs::new(&args, pubs_indices);

    let (vk, pk) = setup_circuit(&*circuit, params).expect("setup should not fail");

    let kzg_scheme = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };

    let proof = prove_circuit((*circuit).clone(), &public_inputs, params, &pk, kzg_scheme)
        .expect("proof generation should not fail");

    Ok(ProveOutput {
        proof,
        instance: public_inputs.to_bytes(),
        vk: vk.to_bytes(SerdeFormat::Processed),
        k,
        public_inputs,
    })
}
