// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::dev::{MockProver, VerifyFailure};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey,
};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::transcript::{TranscriptReadBuffer, TranscriptWriterBuffer};

use halo2_proofs::poly::{
    commitment::ParamsProver,
    ipa::{
        commitment::{IPACommitmentScheme, ParamsIPA},
        multiopen::ProverIPA,
        strategy::SingleStrategy as SingleStrategyIPA,
    },
    kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy as SingleStrategyKZG,
    },
    VerificationStrategy,
};

use crate::loader::MoveLoader;
use crate::native_functions::NativeFunctions;
use crate::state::StateStore;
use logger::prelude::*;
use move_binary_format::errors::PartialVMResult;
use move_binary_format::file_format::{Bytecode, CompiledScript};
use move_binary_format::CompiledModule;
use movelang::argument::{convert_type_tag_to_type, ScriptArguments, Signer};
use movelang::value::TypeTag;
use plotters::prelude::*;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::marker::PhantomData;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::arith_operations::ArithOperations;
use vm_circuit::witness::bytecode_table::BytecodeTable;
use vm_circuit::witness::call_trace_table::{pos_to_id, CallTraceTable, NameToIdxMapping};
use vm_circuit::witness::const_table::ConstantTable;
use vm_circuit::witness::execution_steps::{ExecutionData, GenericTypeData, MaterializedTypeInfo};
use vm_circuit::witness::function_calls::FunctionCalls;
use vm_circuit::witness::input_type_elements::{InputTypeElement, InputTypeElementTableData};
use vm_circuit::witness::type_instantiation_table::{
    flatten_materialized_type, map_type_name, GenericTypeInstantiationTableData,
};
use vm_circuit::witness::{CircuitConfig, Witness};

// number of circuit rows cannot exceed 2^MAX_K
pub const MAX_K: u32 = 18;
pub const MIN_K: u32 = 1;

pub struct Runtime<F: FieldExt> {
    loader: MoveLoader,
    natives: NativeFunctions<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Default for Runtime<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldExt> Runtime<F> {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new_with_natives(crate::natives::make_all()),
            natives: NativeFunctions::new(crate::natives::make_all_field_version()).unwrap(),
            _marker: PhantomData,
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_script(
        &self,
        script: CompiledScript,
        modules: Vec<CompiledModule>,
        ty_args: Vec<TypeTag>,
        signer: Option<Signer>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore<F>,
        circuit_config: CircuitConfig,
    ) -> VmResult<Witness<F>> {
        let mut interp = Interpreter::<F>::new();
        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;

        let (entry, type_arguments) = self
            .loader()
            .load_script(&script_bytes, &ty_args, data_store)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                RuntimeError::new(StatusCode::ScriptLoadingError)
            })?;
        trace!("script entry {:?}", entry.name());
        let arg_types = entry
            .parameter_types()
            .iter()
            .map(|ty| ty.subst(&type_arguments))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|e| {
                error!("arg_types unification fail. {:?}", e);
                RuntimeError::new(StatusCode::TypeMismatch)
            })?;
        let mut exec_steps = Vec::new();
        let mut rw_operations = Vec::new();
        let mut generic_types = Vec::new();
        interp.run_script(
            &script,
            entry,
            type_arguments,
            signer,
            args,
            arg_types,
            self.loader(),
            data_store,
            &self.natives,
            &mut exec_steps,
            &mut rw_operations,
            &mut generic_types,
        )?;
        let mapping = NameToIdxMapping::build(&modules);
        let normalized_input_type_args: Vec<_> =
            ty_args.into_iter().map(convert_type_tag_to_type).collect();
        let input_type_element_table_data = normalized_input_type_args
            .iter()
            .enumerate()
            .flat_map(|(idx, t)| flatten_materialized_type(vec![idx as u8 + 1], t, t))
            .map(|te| {
                let (m, s) = map_type_name(&mapping, &te.data);
                (pos_to_id(&te.materialized_pos), m, s.0)
            })
            .map(|(pos, module, name)| InputTypeElement {
                ty_arg_pos: pos,
                ty_arg_module: module,
                ty_arg_name: name,
            })
            .collect();

        let exec_datas: HashMap<usize, ExecutionData> = generic_types
            .iter()
            .map(|ti| {
                let materialized_type_elements = ti
                    .type_args
                    .iter()
                    .enumerate()
                    .flat_map(|(i, inst_type)| {
                        flatten_materialized_type(
                            vec![i as u8 + 1],
                            &inst_type.subst(&normalized_input_type_args),
                            inst_type,
                        )
                    })
                    .map(|te| {
                        let (m, s) = map_type_name(&mapping, &te.data);
                        MaterializedTypeInfo {
                            inst_ty_pos: pos_to_id(&te.instantiation_pos),
                            inst_ty_pos_max: 2u128.pow(te.instantiation_pos.len() as u32 * 8),
                            referred_param_index: te.referred_ty_idx.unwrap_or(0),
                            ty_arg_pos: pos_to_id(&te.materialized_pos),
                            ty_arg_module: m,
                            ty_arg_name: s.0,
                        }
                    })
                    .collect::<Vec<_>>();
                (
                    ti.execution_step_index,
                    match ti.op {
                        Bytecode::CallGeneric(_) => ExecutionData::CallGeneric(GenericTypeData {
                            generic_types: materialized_type_elements,
                        }),
                        _ => ExecutionData::StorageOp(GenericTypeData {
                            generic_types: materialized_type_elements,
                        }),
                    },
                )
            })
            .collect();
        exec_datas.into_iter().for_each(|(idx, data)| {
            exec_steps
                .get_mut(idx)
                .unwrap_or_else(|| panic!("exec step at {} not exist", idx))
                .data = Some(data);
        });

        let arith_operations = ArithOperations::from((&script, modules.as_slice())).0;
        let func_calls = FunctionCalls::from((&script, modules.as_slice())).0;
        let call_traces = CallTraceTable::from((&script, modules.as_slice()));
        let type_instantiations =
            GenericTypeInstantiationTableData::from((&script, modules.as_slice()));
        let constants = ConstantTable::from(modules.as_slice());
        let bytecodes = BytecodeTable::from((script.clone(), modules));

        Ok(Witness::new(
            exec_steps,
            rw_operations,
            bytecodes,
            constants,
            func_calls,
            arith_operations,
            call_traces,
            type_instantiations,
            InputTypeElementTableData(input_type_element_table_data),
            circuit_config,
        ))
    }
}

impl<F: FieldExt> Runtime<F> {
    // find the minimum k that satisfies the circuit row number less than 2^k
    pub fn find_best_k<ConcreteCircuit: Circuit<F>>(
        &self,
        circuit: &ConcreteCircuit,
        instance: Vec<Vec<F>>,
    ) -> VmResult<u32> {
        let mut k = MIN_K;
        while k <= MAX_K {
            trace!("Try k={}...", k);
            let not_enough_rows_error = Error::NotEnoughRowsAvailable { current_k: k };
            let result = MockProver::run(k, circuit, instance.clone());
            match result {
                Ok(r) => {
                    // Ensure that no constraints will get poisoned.
                    // This can happen if the circuit is principally big enough, but the
                    // constraint count exceeds the number of usable rows
                    // (2^k - 1 - blinding_factors).
                    let _ = r.verify().map_err(|e| {
                        if e.iter()
                            .any(|e| matches!(e, VerifyFailure::ConstraintPoisoned { .. }))
                        {
                            k += 1;
                        }
                    });
                    break;
                }
                Err(e) => {
                    if e.to_string() == not_enough_rows_error.to_string() {
                        k += 1;
                    } else {
                        debug!("Prover Error: {:?}", e);
                        return Err(RuntimeError::new(StatusCode::ProofSystemError(e)));
                    }
                }
            }
        }
        Ok(k)
    }

    pub fn mock_prove_circuit<ConcreteCircuit: Circuit<F>>(
        &self,
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

    pub fn print_circuit_layout<ConcreteCircuit: Circuit<F>>(
        &self,
        k: u32,
        circuit: &ConcreteCircuit,
    ) {
        let root = SVGBackend::new("layout.svg", (3840, 2160)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Circuit Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .mark_equality_cells(true)
            .show_equality_constraints(true)
            .render(k, circuit, &root)
            .unwrap();
    }
}

/// setup prove system's PCS with KZG
impl<F: FieldExt> Runtime<F>
where
    VmCircuit<F>: Circuit<Fr>,
{
    pub fn setup_vm_circuit_kzg(
        &self,
        circuit: &VmCircuit<F>,
        params: &ParamsKZG<Bn256>,
    ) -> VmResult<ProvingKey<G1Affine>> {
        debug!("Generate vk");
        let vk = keygen_vk(params, circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_vk should not fail".to_string())
        })?;
        debug!("Generate pk");
        let pk = keygen_pk(params, vk, circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_pk should not fail".to_string())
        })?;
        Ok(pk)
    }

    pub fn prove_vm_circuit_kzg(
        &self,
        circuit: VmCircuit<F>,
        instance: &[&[Fr]],
        params: &ParamsKZG<Bn256>,
        pk: ProvingKey<G1Affine>,
    ) -> VmResult<()> {
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let prove_start = std::time::Instant::now();
        let rng = StdRng::from_entropy();
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(params, &pk, &[circuit], &[instance], rng, &mut transcript)
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        info!("proof size {} bytes", proof.len());
        let prove_time = std::time::Instant::now().duration_since(prove_start);
        info!("prove time: {} ms", prove_time.as_millis());

        // verify the proof
        let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategyKZG::new(params);

        // Bench verification time
        let verify_start = std::time::Instant::now();
        let result = verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategyKZG<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[instance],
            &mut verifier_transcript,
        );

        let verify_time = std::time::Instant::now().duration_since(verify_start);
        info!("verify time: {} ms", verify_time.as_millis());
        debug!("{:?}", result);
        assert!(result.is_ok());
        Ok(())
    }
}

/// setup prove system's PCS with IPA
impl<F: FieldExt> Runtime<F>
where
    VmCircuit<F>: Circuit<Fp>,
{
    pub fn setup_vm_circuit_ipa(
        &self,
        circuit: &VmCircuit<F>,
        params: &ParamsIPA<EqAffine>,
    ) -> VmResult<ProvingKey<EqAffine>> {
        debug!("Generate vk");
        let vk = keygen_vk(params, circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_vk should not fail".to_string())
        })?;
        debug!("Generate pk");
        let pk = keygen_pk(params, vk, circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_pk should not fail".to_string())
        })?;
        Ok(pk)
    }

    pub fn prove_vm_circuit_ipa(
        &self,
        circuit: VmCircuit<F>,
        instance: &[&[Fp]],
        params: &ParamsIPA<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<EqAffine>>::init(vec![]);
        // Create a proof
        let prove_start = std::time::Instant::now();
        let rng = StdRng::from_entropy();
        create_proof::<IPACommitmentScheme<EqAffine>, ProverIPA<EqAffine>, _, _, _, _>(
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
        let prove_time = std::time::Instant::now().duration_since(prove_start);
        info!("prove time: {} ms", prove_time.as_millis());

        let strategy = SingleStrategyIPA::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verify_start = std::time::Instant::now();
        let result = verify_proof(params, pk.get_vk(), strategy, &[instance], &mut transcript);

        let verify_time = std::time::Instant::now().duration_since(verify_start);
        info!("verify time: {} ms", verify_time.as_millis());
        debug!("{:?}", result);
        assert!(result.is_ok());
        Ok(())
    }
}
