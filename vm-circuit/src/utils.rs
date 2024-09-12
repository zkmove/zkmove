#![allow(unused_variables)]
pub mod cached_region;
pub mod cell_manager;
pub mod cell_placement_strategy;
pub mod challenges;
pub mod rlc;
pub mod word;
use crate::circuit::VmCircuit;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::halo2curves::pairing::{Engine, MultiMillerLoop};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error, ProvingKey,
    VerifyingKey, VirtualCells,
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
use crate::utils::challenges::Challenges;
use crate::witness::WitnessV2;
use field_exts::U256;
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::CurveExt;
use itertools::Itertools;
use logger::{debug, info};
use plotters::prelude::{IntoDrawingArea, SVGBackend, WHITE};
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::fmt::Debug;
use types::Field;

pub(crate) fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0u64.expr())
    });
    expr.unwrap()
}

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
    dbg!(prover.cs().num_advice_columns());
    dbg!(prover.cs().num_instance_columns());
    dbg!(prover.cs().num_fixed_columns());
    dbg!(prover.cs().num_selectors());
    dbg!(prover
        .cs()
        .gates()
        .iter()
        .map(|g| g.polynomials().len())
        .sum::<usize>());
    dbg!(prover.cs().advice_queries().len());
    // uncomment this to output assignments
    {
        let mut f = std::fs::File::options()
            .write(true)
            .truncate(true)
            .create(true)
            .open("assign-advice.csv")
            .unwrap();
        use std::io::Write;
        for column_data in prover.advice() {
            let cols = column_data
                .iter()
                .take(128)
                .map(|c| match c {
                    halo2_proofs::dev::CellValue::Unassigned => String::default(),
                    halo2_proofs::dev::CellValue::Assigned(f) => {
                        format!("{}", U256::from_little_endian(f.to_repr().as_ref()))
                    }
                    halo2_proofs::dev::CellValue::Poison(p) => {
                        format!("p({})", p)
                    }
                })
                .join(",");

            writeln!(&mut f, "{}", cols).unwrap();
        }
    }
    {
        let mut f = std::fs::File::options()
            .write(true)
            .truncate(true)
            .create(true)
            .open("assign-fixed.csv")
            .unwrap();
        use std::io::Write;
        for column_data in prover.fixed() {
            let cols = column_data
                .iter()
                .take(128)
                .map(|c| match c {
                    halo2_proofs::dev::CellValue::Unassigned => String::default(),
                    halo2_proofs::dev::CellValue::Assigned(f) => {
                        format!("{}", U256::from_little_endian(f.to_repr().as_ref()))
                    }
                    halo2_proofs::dev::CellValue::Poison(p) => {
                        format!("p({})", p)
                    }
                })
                .join(",");

            writeln!(&mut f, "{}", cols).unwrap();
        }
    }
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
    ConcreteCircuit: Circuit<C::ScalarExt>,
    C::ScalarExt: FromUniformBytes<64>,
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

pub fn prove_vm_circuit_ipa<C: CurveAffine, ConcreteCircuit: Circuit<C::ScalarExt>>(
    circuit: ConcreteCircuit,
    instance: &[&[C::ScalarExt]],
    params: &ParamsIPA<C>,
    pk: ProvingKey<C>,
) -> VmResult<Vec<u8>>
where
    C::ScalarExt: FromUniformBytes<64>,
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
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> VmResult<Vec<u8>>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
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
// TODO: rework on these functions.
pub fn proof_vm_circuit_kzg<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> VmResult<Vec<u8>>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
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
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
    proof: Vec<u8>,
) -> VmResult<()>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
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

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full move verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        256
    }

    /// Create a new SubCircuit from a witness Block
    fn new_from_witness(witness: &WitnessV2) -> Self;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Return the minimum number of rows required to prove the witness.
    /// Row numbers without/with padding are both returned.
    fn min_num_rows(witness: &WitnessV2) -> (usize, usize);
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}
