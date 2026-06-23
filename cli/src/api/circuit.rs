// Copyright (c) zkMove Authors

//! Shared circuit construction used by proving, verifier testing and txn building.

use anyhow::Result;
use halo2::proofs::best_k;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::info;
use move_package::compilation::compiled_package::CompiledPackage;
use std::rc::Rc;
use vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use witness::static_info::{EntryInfo, Footprints};

/// Build the circuit from a witness.
///
/// Returns the circuit and its [`CircuitGuard`] (the caller MUST keep it alive while
/// using the circuit, since the circuit config lives in thread-local storage).
pub fn build_circuit(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
) -> Result<(Rc<VmCircuit<Fr>>, CircuitGuard)> {
    let circuit = Rc::new(
        VmCircuit::<Fr>::try_new(package, traces, pubs_indices, config)
            .map_err(anyhow::Error::msg)?,
    );
    let guard = CircuitGuard::new(circuit.clone());
    Ok((circuit, guard))
}

/// Build the empty-state circuit used during app-developer setup and local verify.
///
/// Returns the circuit and its [`CircuitGuard`] (the caller MUST keep it alive while
/// using the circuit, since the circuit config lives in thread-local storage).
pub fn build_empty_circuit(
    package: &CompiledPackage,
    entry_info: EntryInfo,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
) -> Result<(Rc<VmCircuit<Fr>>, CircuitGuard)> {
    let circuit = Rc::new(
        VmCircuit::<Fr>::try_new_with_empty_state(package, entry_info, pubs_indices, config)
            .map_err(anyhow::Error::msg)?,
    );
    let guard = CircuitGuard::new(circuit.clone());
    Ok((circuit, guard))
}

/// Build the circuit from a witness, pick the optimal `k`, and downsize `params` to it.
///
/// Returns the circuit, its [`CircuitGuard`] (the caller MUST keep it alive while using
/// the circuit, since the circuit config lives in thread-local storage), and `k`.
pub fn build_circuit_and_fit_params(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
) -> Result<(Rc<VmCircuit<Fr>>, CircuitGuard, u32)> {
    let (circuit, guard) = build_circuit(package, traces, config, pubs_indices)?;

    let k = best_k(&circuit);
    info!("Optimal k = {}", k);
    if k < params.k() {
        params.downsize(k);
    }

    Ok((circuit, guard, k))
}

/// Build the empty-state circuit, pick the optimal `k`, and downsize `params` to it.
pub fn build_empty_circuit_and_fit_params(
    package: &CompiledPackage,
    entry_info: EntryInfo,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
) -> Result<(Rc<VmCircuit<Fr>>, CircuitGuard, u32)> {
    let (circuit, guard) = build_empty_circuit(package, entry_info, config, pubs_indices)?;

    let k = best_k(&circuit);
    info!("Optimal setup k = {}", k);
    if k < params.k() {
        params.downsize(k);
    }

    Ok((circuit, guard, k))
}
