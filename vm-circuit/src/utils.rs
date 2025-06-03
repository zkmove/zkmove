pub mod cached_region;
pub mod cell_manager;
pub mod cell_placement_strategy;
pub mod challenges;
pub mod rlc;
pub mod word;
use crate::utils::challenges::Challenges;
use crate::{CircuitConfigV2, Footprints, VmCircuit};
use aptos_move_witnesses::static_info::EntryInfo;
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        ff::{FromUniformBytes, WithSmallOrderMulGroup},
        pairing::{Engine, MultiMillerLoop},
        serde::SerdeObject,
        CurveExt,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        ProvingKey, VerifyingKey, VirtualCells,
    },
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::strategy::SingleStrategy,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use itertools::Itertools;
use logger::{debug, info};
use move_package::compilation::compiled_package::CompiledPackage;
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

// number of circuit rows cannot exceed 2^MAX_DEGREE
pub const MAX_DEGREE: u32 = 18;
pub const MIN_DEGREE: u32 = 11;

pub fn best_k<F: Field>(circuit: &VmCircuit<F>) -> u32 {
    /// Ceiling of log_2(n)
    fn log2_ceil(n: usize) -> u32 {
        u32::BITS - (n as u32).leading_zeros() - n.is_power_of_two() as u32
    }
    std::cmp::max(log2_ceil(circuit.circuit_height()), MIN_DEGREE)
}

pub fn print_cs_info<F: Field>(cs: &ConstraintSystem<F>) {
    dbg!(cs.degree());
    dbg!(cs.blinding_factors());
    dbg!(cs.minimum_rows());
    dbg!(cs.num_advice_columns());
    dbg!(cs.num_instance_columns());
    dbg!(cs.num_fixed_columns());
    dbg!(cs.num_selectors());
    dbg!(cs
        .gates()
        .iter()
        .map(|g| g.polynomials().len())
        .sum::<usize>());
    dbg!(cs.advice_queries().len());
    dbg!(cs.lookups().len());
    dbg!(cs.shuffles().len());
    dbg!(cs.advice_column_phase().iter().counts_by(|p| *p));
}

pub fn mock_prove_circuit<F: Field, ConcreteCircuit: Circuit<F>>(
    circuit: &ConcreteCircuit,
    instance: Vec<Vec<F>>,
    k: u32,
) -> Result<(), Error> {
    let prover = MockProver::run(k, circuit, instance)?;
    print_cs_info(prover.cs());

    // uncomment this to output assignments
    // {
    //     use std::io::Write;
    //     let mut f = std::fs::File::options()
    //         .write(true)
    //         .truncate(true)
    //         .create(true)
    //         .open("assign-selector.csv")
    //         .unwrap();
    //     writeln!(
    //         &mut f,
    //         "{}",
    //         (1..=prover.selectors().first().map(|v| v.len()).unwrap())
    //             .map(|i| i.to_string())
    //             .join(",")
    //     )
    //     .unwrap();
    //
    //     for x in prover.selectors() {
    //         let row = x.iter().map(|b| if *b { "1" } else { "0" }).join(",");
    //         writeln!(&mut f, "{}", row).unwrap();
    //     }
    //
    //     let mut f = std::fs::File::options()
    //         .write(true)
    //         .truncate(true)
    //         .create(true)
    //         .open("assign-advice.csv")
    //         .unwrap();
    //
    //     for column_data in prover.advice() {
    //         let cols = column_data
    //             .iter()
    //             .take(512)
    //             .map(|c| match c {
    //                 halo2_proofs::dev::CellValue::Unassigned => String::default(),
    //                 halo2_proofs::dev::CellValue::Assigned(f) => {
    //                     format!("{}", U256::from_little_endian(f.to_repr().as_ref()))
    //                 }
    //                 halo2_proofs::dev::CellValue::Poison(p) => {
    //                     format!("p({})", p)
    //                 }
    //             })
    //             .join(",");
    //
    //         writeln!(&mut f, "{}", cols).unwrap();
    //     }
    // }
    // {
    //     let mut f = std::fs::File::options()
    //         .write(true)
    //         .truncate(true)
    //         .create(true)
    //         .open("assign-fixed.csv")
    //         .unwrap();
    //     use std::io::Write;
    //     for column_data in prover.fixed() {
    //         let cols = column_data
    //             .iter()
    //             .take(256)
    //             .map(|c| match c {
    //                 halo2_proofs::dev::CellValue::Unassigned => String::default(),
    //                 halo2_proofs::dev::CellValue::Assigned(f) => {
    //                     format!("{}", U256::from_little_endian(f.to_repr().as_ref()))
    //                 }
    //                 halo2_proofs::dev::CellValue::Poison(p) => {
    //                     format!("p({})", p)
    //                 }
    //             })
    //             .join(",");
    //
    //         writeln!(&mut f, "{}", cols).unwrap();
    //     }
    // }
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

/// Sets up a circuit by generating verification and proving keys.
///
/// # Arguments
/// - `circuit`: The circuit to generate keys for.
/// - `params`: The KZG parameters for the curve.
///
/// # Returns
/// A tuple containing the `VerifyingKey` and `ProvingKey` if successful.
pub fn setup_circuit<'params, C, P, ConcreteCircuit>(
    circuit: &ConcreteCircuit,
    params: &P,
) -> Result<(VerifyingKey<C>, ProvingKey<C>), Error>
where
    C: CurveAffine,
    P: Params<'params, C>,
    ConcreteCircuit: Circuit<C::ScalarExt>,
    C::ScalarExt: FromUniformBytes<64>,
{
    debug!("Generate vk");
    let vk = keygen_vk(params, circuit)?;
    debug!("Generate pk");
    let pk = keygen_pk(params, vk.clone(), circuit)?;
    Ok((vk, pk))
}
/// Proves a circuit using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `circuit`: The circuit to prove.
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `pk`: The proving key.
///
/// # Returns
/// The proof as a byte vector if successful.
pub fn prove_circuit<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: &ProvingKey<E::G1Affine>,
) -> Result<Vec<u8>, Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    prove_circuit_inner::<KZGCommitmentScheme<E>, ProverSHPLONK<E>, _>(
        circuit, instance, params, pk,
    )
}
fn prove_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: &ProvingKey<Scheme::Curve>,
) -> Result<Vec<u8>, Error>
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
        pk,
        &[circuit],
        &[instance],
        rng,
        &mut transcript,
    )?;
    let proof: Vec<u8> = transcript.finalize();
    info!("proof size {} bytes", proof.len());
    let prove_time = instant::Instant::now().duration_since(prove_start);
    info!("prove time: {} ms", prove_time.as_millis());

    Ok(proof)
}

/// Verifies a circuit proof using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `vk`: The verification key.
/// - `proof`: The proof bytes to verify.
///
/// # Returns
/// `Ok(())` if the proof is valid, or an error if verification fails.
pub fn verify_circuit<E>(
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    vk: &VerifyingKey<E::G1Affine>,
    proof: &Vec<u8>,
) -> Result<(), Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    verify_circuit_inner::<KZGCommitmentScheme<E>, VerifierSHPLONK<E>, SingleStrategy<E>>(
        instance, params, vk, proof,
    )
}
fn verify_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
>(
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: &Vec<u8>,
) -> Result<(), Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let verifier_params = params.verifier_params();
    let strategy = Strategy::new(verifier_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_start = instant::Instant::now();
    let result = verify_proof(verifier_params, vk, strategy, &[instance], &mut transcript)?;

    let verify_time = instant::Instant::now().duration_since(verify_start);
    info!("verify time: {} ms", verify_time.as_millis());
    Ok(())
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full move verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
#[allow(clippy::too_long_first_doc_paragraph)]
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        256
    }

    /// Create a new SubCircuit
    fn new(
        package: &CompiledPackage,
        traces: &Footprints,
        pubs_indices: &[usize],
        config: CircuitConfigV2,
    ) -> Self;
    /// Create a new SubCircuit with empty state
    fn new_with_empty_state(
        package: &CompiledPackage,
        entry: EntryInfo,
        pubs_indices: &[usize],
        config: CircuitConfigV2,
    ) -> Self;
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
    /// Register the circuit in thread-local registry.
    fn register(&self);
    fn unregister(&self);
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}
