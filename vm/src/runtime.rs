// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use error::{RuntimeError, StatusCode, VmResult};
use fast_circuit::circuit::MoveCircuit;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::{dev::MockProver, pasta::EqAffine, pasta::Fp};
use logger::prelude::*;
use move_binary_format::file_format::CompiledScript;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::state::StateStore;
use rand_core::OsRng;
use std::marker::PhantomData;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::bytecode_table::BytecodeTable;
use vm_circuit::witness::{CircuitConfig, Witness};

// number of circuit rows cannot exceed 2^MAX_K
pub const MAX_K: u32 = 18;
pub const MIN_K: u32 = 1;

pub const MAX_STEPS_NUM: usize = 1000;
pub const MAX_OPS_NUM: usize = 1000;

pub struct Runtime<F: FieldExt> {
    loader: MoveLoader,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Runtime<F> {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new(),
            _marker: PhantomData,
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }

    pub fn create_move_circuit(
        &self,
        script: CompiledScript,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: StateStore,
    ) -> MoveCircuit {
        MoveCircuit::new(script, modules, args, data_store, self.loader())
    }

    pub fn execute_script(
        &self,
        script: CompiledScript,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: &StateStore,
        steps_num: Option<usize>,
        stack_ops_num: Option<usize>,
        locals_ops_num: Option<usize>,
    ) -> VmResult<Witness<F>> {
        let mut interp = Interpreter::<F>::new();
        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;

        let (entry, arg_types) = self
            .loader()
            .load_script(&script_bytes, data_store)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                RuntimeError::new(StatusCode::ScriptLoadingError)
            })?;
        debug!("script entry {:?}", entry.name());

        let mut exec_steps = Vec::new();
        let mut rw_operations = Vec::new();
        interp.run_script(
            entry,
            args,
            arg_types,
            self.loader(),
            data_store,
            &mut exec_steps,
            &mut rw_operations,
        )?;

        let bytecodes = BytecodeTable::from((script.clone(), modules.clone()));
        let circuit_config = CircuitConfig {
            steps_num,
            stack_ops_num,
            locals_ops_num,
        };
        Ok(Witness::new(
            exec_steps,
            rw_operations,
            bytecodes,
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
            debug!("Try k={}...", k);
            let not_enough_rows_error = Error::NotEnoughRowsAvailable { current_k: k };
            let result = MockProver::run(k, circuit, instance.clone());
            match result {
                Ok(_) => {
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
}

impl<F: FieldExt> Runtime<F>
where
    VmCircuit<F>: Circuit<Fp>,
{
    pub fn setup_move_circuit(
        &self,
        circuit: &MoveCircuit,
        params: &Params<EqAffine>,
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

    pub fn setup_vm_circuit(
        &self,
        circuit: &VmCircuit<F>,
        params: &Params<EqAffine>,
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

    pub fn prove_move_circuit(
        &self,
        circuit: MoveCircuit,
        instance: &[&[Fp]],
        params: &Params<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        let prove_start = std::time::Instant::now();
        create_proof(params, &pk, &[circuit], &[instance], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        info!("proof size {} bytes", proof.len());
        let prove_time = std::time::Instant::now().duration_since(prove_start);
        info!("prove time: {} ms", prove_time.as_millis());

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verify_start = std::time::Instant::now();
        let result = verify_proof(params, pk.get_vk(), strategy, &[instance], &mut transcript);
        let verify_time = std::time::Instant::now().duration_since(verify_start);
        info!("verify time: {} ms", verify_time.as_millis());
        info!("{:?}", result);
        assert!(result.is_ok());
        Ok(())
    }

    pub fn prove_vm_circuit(
        &self,
        circuit: VmCircuit<F>,
        instance: &[&[Fp]],
        params: &Params<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        let prove_start = std::time::Instant::now();
        create_proof(params, &pk, &[circuit], &[instance], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        info!("proof size {} bytes", proof.len());
        let prove_time = std::time::Instant::now().duration_since(prove_start);
        info!("prove time: {} ms", prove_time.as_millis());

        let strategy = SingleVerifier::new(params);
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
