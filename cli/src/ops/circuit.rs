// Copyright (c) zkMove Authors

//! Shared circuit construction used by proving, verifier testing and txn building.

use halo2::proofs::best_k;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::info;
use move_package::compilation::compiled_package::CompiledPackage;
use std::rc::Rc;
use vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use witness::static_info::Footprints;

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
) -> (Rc<VmCircuit<Fr>>, CircuitGuard, u32) {
    let circuit = Rc::new(VmCircuit::<Fr>::new(package, traces, pubs_indices, config));
    let guard = CircuitGuard::new(circuit.clone());

    let k = best_k(&circuit);
    info!("Optimal k = {}", k);
    if k < params.k() {
        params.downsize(k);
    }

    (circuit, guard, k)
}
