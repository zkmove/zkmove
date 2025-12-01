use field_exts::Field;
use halo2_backend::transcript::{Keccak256Read, Keccak256Write};
use halo2_proofs::dev::MockProver;
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
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
        ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{CommitmentScheme, Params, Prover, Verifier},
        kzg::strategy::SingleStrategy,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        VerificationStrategy,
    },
    transcript::{Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use log::debug;
use log::info;
use poseidon_base::Hashable;
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::fmt::Debug;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::VmCircuit;

pub use witness::static_info::{EntryInfo, ModuleIdMapping};

// number of circuit rows cannot exceed 2^MAX_DEGREE
pub const MAX_DEGREE: u32 = 18;
pub const MIN_DEGREE: u32 = 9;

pub fn best_k<F: Field + Hashable>(circuit: &VmCircuit<F>) -> u32 {
    /// Ceiling of log_2(n)
    fn log2_ceil(n: usize) -> u32 {
        u32::BITS - (n as u32).leading_zeros() - n.is_power_of_two() as u32
    }
    let k = std::cmp::max(log2_ceil(circuit.circuit_height()), MIN_DEGREE);
    debug!("best_k: {}", k);
    k
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
    instance: &PublicInputs<F>,
    k: u32,
) -> Result<(), Error> {
    let prover = MockProver::run(k, circuit, instance.as_vec())?;
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

/// Sets up a circuit by generating verification and proving keys.
///
/// # Arguments
/// - `circuit`: The circuit to generate keys for.
/// - `params`: The KZG parameters for the curve.
///
/// # Returns
/// A tuple containing the `VerifyingKey` and `ProvingKey` if successful.
pub fn setup_circuit<C, P, ConcreteCircuit>(
    circuit: &ConcreteCircuit,
    params: &P,
) -> Result<(VerifyingKey<C>, ProvingKey<C>), Error>
where
    C: CurveAffine,
    P: Params<C>,
    ConcreteCircuit: Circuit<C::ScalarExt>,
    C::ScalarExt: FromUniformBytes<64>,
{
    debug!("Generate vk");
    let vk = keygen_vk(params, circuit)?;
    debug!("Generate pk");
    let pk = keygen_pk(params, vk.clone(), circuit)?;
    Ok((vk, pk))
}

#[derive(Copy, Clone, Debug)]
pub enum KZG {
    GWC,
    SHPLONK,
}

impl KZG {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::SHPLONK => 0,
            Self::GWC => 1,
        }
    }
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
    instance: &PublicInputs<E::Fr>,
    params: &ParamsKZG<E>,
    pk: &ProvingKey<E::G1Affine>,
    kzg: KZG,
) -> Result<Vec<u8>, Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
    <E as Engine>::Fr: Field,
{
    match kzg {
        KZG::GWC => prove_circuit_inner::<KZGCommitmentScheme<E>, ProverGWC<E>, _>(
            circuit,
            instance.as_vec(),
            params,
            pk,
        ),
        KZG::SHPLONK => prove_circuit_inner::<KZGCommitmentScheme<E>, ProverSHPLONK<E>, _>(
            circuit,
            instance.as_vec().clone(),
            params,
            pk,
        ),
    }
}
fn prove_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: Vec<Vec<Scheme::Scalar>>,
    params: &'params Scheme::ParamsProver,
    pk: &ProvingKey<Scheme::Curve>,
) -> Result<Vec<u8>, Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Keccak256Write::<Vec<u8>, _, Challenge255<_>>::init(vec![]);

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
    instance: &PublicInputs<E::Fr>,
    params: &ParamsKZG<E>,
    vk: &VerifyingKey<E::G1Affine>,
    proof: &Vec<u8>,
    kzg: KZG,
) -> Result<(), Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
    <E as Engine>::Fr: Field,
{
    match kzg {
        KZG::GWC => {
            verify_circuit_inner::<KZGCommitmentScheme<E>, VerifierGWC<E>, SingleStrategy<E>>(
                instance.as_vec(),
                &params.verifier_params(),
                vk,
                proof,
            )
        }
        KZG::SHPLONK => verify_circuit_inner::<
            KZGCommitmentScheme<E>,
            VerifierSHPLONK<E>,
            SingleStrategy<E>,
        >(instance.as_vec(), &params.verifier_params(), vk, proof),
    }
}
fn verify_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
>(
    instance: Vec<Vec<Scheme::Scalar>>,
    params: &'params Scheme::ParamsVerifier,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: &Vec<u8>,
) -> Result<(), Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let strategy = Strategy::new(params);
    let mut transcript = Keccak256Read::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_start = instant::Instant::now();
    let _result = verify_proof(params, vk, strategy, &[instance], &mut transcript)?;

    let verify_time = instant::Instant::now().duration_since(verify_start);
    info!("verify time: {} ms", verify_time.as_millis());
    Ok(())
}
