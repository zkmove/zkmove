use crate::aggregation;
use crate::test::vm_circuit_example::SimpleVmCircuit;
use error::VmResult;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use logger::prelude::info;
use rand::rngs::OsRng;
use snark_verifier::{
    loader::native::NativeLoader,
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
};
use std::io::Cursor;

mod vm_circuit_example {
    use error::{RuntimeError, StatusCode};
    use halo2_proofs::arithmetic::FieldExt;
    use move_binary_format::file_format::empty_script;
    use move_binary_format::file_format::Bytecode;
    use move_binary_format::CompiledModule;
    use movelang::generic_call_graph::generate_for_script;
    use vm::interpreter::Interpreter;
    use vm::runtime::Runtime;
    use vm::state::StateStore;
    use vm_circuit::circuit::VmCircuit;
    use vm_circuit::witness::arith_operations::ArithOperations;
    use vm_circuit::witness::{CircuitConfig, Witness};

    pub struct SimpleVmCircuit<F: FieldExt> {
        circuit: VmCircuit<F>,
    }

    impl<F: FieldExt> SimpleVmCircuit<F> {
        pub fn new() -> Self {
            let mut script = empty_script();
            script.code.code = vec![
                Bytecode::LdU64(1u64),
                Bytecode::LdU64(2u64),
                Bytecode::Add,
                Bytecode::Pop,
                Bytecode::Ret,
            ];
            let bytecodes = (script.clone(), vec![]).into();
            let deps: &[CompiledModule] = &[];
            let arith_operations = ArithOperations::from((Some(&script), deps)).0;
            let mut blob = vec![];
            script.serialize(&mut blob).expect("script must serialize");

            let runtime = Runtime::<F>::new();
            let mut data_store = StateStore::new();
            let mut interp = Interpreter::<F>::new();
            let generic_graph = generate_for_script(&script, &data_store);

            let (entry, ty_arguments) = runtime
                .loader()
                .load_script(&blob, &[], &data_store)
                .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))
                .unwrap();
            let arg_types = entry.parameter_types().to_vec();
            let mut exec_steps = Vec::new();
            let mut rw_operations = Vec::new();
            let mut generic_type_infos = Vec::new();
            interp
                .execute_function(
                    entry,
                    ty_arguments,
                    None,
                    None,
                    arg_types,
                    runtime.loader(),
                    &mut data_store,
                    runtime.get_natives(),
                    runtime.get_native_context_exts(),
                    &mut exec_steps,
                    &mut rw_operations,
                    &mut generic_type_infos,
                    &generic_graph,
                )
                .unwrap();

            let circuit_config = CircuitConfig::default();
            let witness = Witness::new(
                exec_steps,
                rw_operations,
                bytecodes,
                Default::default(),
                vec![],
                arith_operations,
                Default::default(),
                Default::default(),
                Default::default(),
                circuit_config,
            );
            let circuit = VmCircuit {
                witness,
                public_input: None,
            };
            SimpleVmCircuit { circuit }
        }

        pub fn circuit(&self) -> &VmCircuit<F> {
            &self.circuit
        }
        pub fn num_instance(&self) -> Vec<usize> {
            vec![0]
        }

        pub fn instances(&self) -> Vec<Vec<F>> {
            vec![vec![]]
        }
    }
}

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> aggregation::Snark {
    let vm_circuit = SimpleVmCircuit::<Fr>::new();
    let pk = gen_pk(params, vm_circuit.circuit());
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg().with_num_instance(vm_circuit.num_instance()),
    );

    let proof = gen_proof::<
        _,
        _,
        aggregation::PoseidonTranscript<NativeLoader, _>,
        aggregation::PoseidonTranscript<NativeLoader, _>,
    >(
        params,
        &pk,
        vm_circuit.circuit().clone(),
        vm_circuit.instances(),
    );
    info!("app proof size {} bytes", proof.len());

    aggregation::Snark::new(protocol, vm_circuit.instances(), proof)
}

#[test]
fn test_aggregation() -> VmResult<()> {
    let params = gen_srs(23);
    let params_app = {
        let mut params = params.clone();
        params.downsize(10);
        params
    };

    let snarks = [gen_application_snark(&params_app)];
    let agg_circuit = aggregation::AggregationCircuit::new(&params, snarks);
    let pk = gen_pk(&params, &agg_circuit);

    let aggr_start = std::time::Instant::now();
    let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
    );
    let prove_time = std::time::Instant::now().duration_since(aggr_start);
    info!("prove time: {} ms", prove_time.as_millis());
    info!("aggregated proof size {} bytes", proof.len());

    Ok(())
}
