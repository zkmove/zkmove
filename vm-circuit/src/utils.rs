#![allow(unused_variables)]

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::pairing::{Engine, MultiMillerLoop};

use crate::circuit::VmCircuit;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField, WithSmallOrderMulGroup};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier};
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::{ipa, kzg, VerificationStrategy};
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
// use instant;
use logger::{debug, info};
use plotters::prelude::{IntoDrawingArea, SVGBackend, WHITE};
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::fmt::Debug;
use types::Field;

// number of circuit rows cannot exceed 2^MAX_K
pub const MAX_K: u32 = 18;
pub const MIN_K: u32 = 1;

/// find the minimum k that satisfies the circuit row number less than 2^k
pub fn find_best_k<F: Field>(circuit: &VmCircuit<F>) -> u32 {
    let mut k = MIN_K;
    while k <= MAX_K && (1 << k) <= circuit.circuit_height() {
        k += 1;
    }
    k
}

pub fn mock_prove_circuit<F: Field, ConcreteCircuit: Circuit<F>>(
    circuit: &ConcreteCircuit,
    instance: Vec<Vec<F>>,
    k: u32,
) -> VmResult<()> {
    let prover = MockProver::run(k, circuit, instance).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}

pub fn print_circuit_layout<F: Field, ConcreteCircuit: Circuit<F>>(
    k: u32,
    circuit: &ConcreteCircuit,
) {
    let root = SVGBackend::new("layout.svg", (3840, 2160)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Circuit Layout", ("sans-serif", 60)).unwrap();

    // CircuitLayout is not available at wasm.
    #[cfg(not(target_arch = "wasm32"))]
    halo2_proofs::dev::CircuitLayout::default()
        .mark_equality_cells(true)
        .show_equality_constraints(true)
        .render(k, circuit, &root)
        .unwrap();
}

pub fn setup_vm_circuit<'params, C, P, ConcreteCircuit>(
    circuit: &ConcreteCircuit,
    params: &P,
) -> VmResult<(VerifyingKey<C>, ProvingKey<C>)>
where
    C: CurveAffine,
    P: Params<'params, C>,
    ConcreteCircuit: Circuit<C::Scalar>,
    C::Scalar: FromUniformBytes<64>,
{
    debug!("Generate vk");
    let vk = keygen_vk(params, circuit).map_err(|e| {
        RuntimeError::new(StatusCode::ProofSystemError(e))
            .with_message("keygen_vk should not fail".to_string())
    })?;
    debug!("Generate pk");
    let pk = keygen_pk(params, vk.clone(), circuit).map_err(|e| {
        RuntimeError::new(StatusCode::ProofSystemError(e))
            .with_message("keygen_pk should not fail".to_string())
    })?;
    Ok((vk, pk))
}

pub fn prove_vm_circuit_ipa<C: CurveAffine, ConcreteCircuit: Circuit<C::Scalar>>(
    circuit: ConcreteCircuit,
    instance: &[&[C::Scalar]],
    params: &ParamsIPA<C>,
    pk: ProvingKey<C>,
) -> VmResult<Vec<u8>>
where
    <C as CurveAffine>::ScalarExt: FromUniformBytes<64>,
{
    prove_vm_circuit::<
        IPACommitmentScheme<C>,
        ProverIPA<C>,
        VerifierIPA<C>,
        ipa::strategy::SingleStrategy<C>,
        _,
    >(circuit, instance, params, pk)
}
pub fn prove_vm_circuit_kzg<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Scalar]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> VmResult<Vec<u8>>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine: SerdeObject,
    E::G2Affine: SerdeObject,
    ConcreteCircuit: Circuit<E::Scalar>,
    <E as Engine>::Scalar: PrimeField,
    <E as Engine>::Scalar: Ord,
    <E as Engine>::Scalar: WithSmallOrderMulGroup<3>,
    <E as Engine>::Scalar: FromUniformBytes<64>,
{
    prove_vm_circuit::<
        KZGCommitmentScheme<E>,
        ProverSHPLONK<E>,
        VerifierSHPLONK<E>,
        kzg::strategy::SingleStrategy<E>,
        _,
    >(circuit, instance, params, pk)
}

// prove circuit,return it proof.
fn prove_vm_circuit<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: ProvingKey<Scheme::Curve>,
) -> VmResult<Vec<u8>>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    let prove_start = instant::Instant::now();
    let rng = StdRng::from_entropy();
    create_proof::<Scheme, P, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &[instance],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    info!("proof size {} bytes", proof.len());
    let prove_time = instant::Instant::now().duration_since(prove_start);
    info!("prove time: {} ms", prove_time.as_millis());

    let verifier_params = params.verifier_params();
    let strategy = Strategy::new(verifier_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_start = instant::Instant::now();
    let result = verify_proof(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[instance],
        &mut transcript,
    );

    let verify_time = instant::Instant::now().duration_since(verify_start);
    info!("verify time: {} ms", verify_time.as_millis());
    assert!(result.is_ok());
    Ok(proof)
}

pub fn proof_vm_circuit_kzg<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Scalar]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> VmResult<Vec<u8>>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine: SerdeObject,
    E::G2Affine: SerdeObject,
    ConcreteCircuit: Circuit<E::Scalar>,
    <E as Engine>::Scalar: PrimeField,
    <E as Engine>::Scalar: Ord,
    <E as Engine>::Scalar: WithSmallOrderMulGroup<3>,
    <E as Engine>::Scalar: FromUniformBytes<64>,
{
    proof_vm_circuit::<KZGCommitmentScheme<E>, ProverSHPLONK<E>, _>(circuit, instance, params, pk)
}

// prove circuit,return it proof.
fn proof_vm_circuit<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: ProvingKey<Scheme::Curve>,
) -> VmResult<Vec<u8>>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    let prove_start = instant::Instant::now();
    let rng = StdRng::from_entropy();
    create_proof::<Scheme, P, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &[instance],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    info!("proof size {} bytes", proof.len());
    let prove_time = instant::Instant::now().duration_since(prove_start);
    info!("prove time: {} ms", prove_time.as_millis());

    Ok(proof)
}

pub fn verify_vm_circuit_kzg<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Scalar]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
    proof: Vec<u8>,
) -> VmResult<()>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine: SerdeObject,
    E::G2Affine: SerdeObject,
    ConcreteCircuit: Circuit<E::Scalar>,
    <E as Engine>::Scalar: PrimeField,
    <E as Engine>::Scalar: Ord,
    <E as Engine>::Scalar: WithSmallOrderMulGroup<3>,
    <E as Engine>::Scalar: FromUniformBytes<64>,
{
    verify_vm_circuit::<
        KZGCommitmentScheme<E>,
        VerifierSHPLONK<E>,
        kzg::strategy::SingleStrategy<E>,
        _,
    >(circuit, instance, params, pk, proof)
}

// prove circuit,return it proof.
fn verify_vm_circuit<
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    _circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: ProvingKey<Scheme::Curve>,
    proof: Vec<u8>,
) -> VmResult<()>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let verifier_params = params.verifier_params();
    let strategy = Strategy::new(verifier_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_start = instant::Instant::now();
    let result = verify_proof(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[instance],
        &mut transcript,
    );

    let verify_time = instant::Instant::now().duration_since(verify_start);
    info!("verify time: {} ms", verify_time.as_millis());
    assert!(result.is_ok());
    Ok(())
}
