// Copyright (c) zkMove Authors

//! Local proof verification logic, decoupled from CLI argument parsing and file IO.

use crate::common::KZGVariant;
use anyhow::Result;
use halo2::proofs::{verify_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::keygen_vk,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::debug;
use move_package::compilation::compiled_package::CompiledPackage;
use std::rc::Rc;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use witness::static_info::EntryInfo;

/// Verify a proof locally by rebuilding the verifying key from the empty-state circuit.
///
/// `params` may be downsized in place to `k`.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    package: &CompiledPackage,
    entry_info: EntryInfo,
    config: CircuitConfigArgs,
    params: &mut ParamsKZG<Bn256>,
    k: u32,
    pubs_indices: &[usize],
    variant: KZGVariant,
    proof: &[u8],
    pubs_bytes: &[u8],
) -> Result<()> {
    if k < params.k() {
        params.downsize(k);
    }

    let circuit = Rc::new(VmCircuit::<Fr>::new_with_empty_state(
        package,
        entry_info,
        pubs_indices,
        config,
    ));

    let _circuit_guard = CircuitGuard::new(circuit.clone());
    // must be called after CircuitGuard, because vk depends on the circuit config
    let vk = keygen_vk::<_, _, VmCircuit<Fr>>(params, &circuit).expect("keygen_vk should not fail");

    let public_inputs = PublicInputs::from_bytes(pubs_bytes);

    let kzg_scheme = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    verify_circuit(&public_inputs, params, &vk, proof, kzg_scheme)
        .expect("verify proof should be ok");

    debug!("Proof verified successfully");
    Ok(())
}
