// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use error::{RuntimeError, StatusCode, VmResult};
use fast_circuit::move_circuit::FastMoveCircuit;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_proofs::{dev::MockProver, pasta::EqAffine, pasta::Fp};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::state::{State, StateStore};
use rand_core::OsRng;
use std::marker::PhantomData;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::circuit_inputs::bytecode_table::BytecodeTable;
use vm_circuit::circuit_inputs::execution_steps::ExecutionStep;
use vm_circuit::circuit_inputs::rw_operations::RWOperation;
use vm_circuit::circuit_inputs::CircuitInputs;

// number of circuit rows cannot exceed 2^MAX_K
pub const MAX_K: u32 = 18;
pub const MIN_K: u32 = 1;

pub struct Runtime<F: FieldExt> {
    loader: MoveLoader,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Runtime<F>
where
    VmCircuit<F>: Circuit<Fp>,
{
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new(),
            _marker: PhantomData,
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }

    // find the minimum k that satisfies the circuit row number less than 2^k
    pub fn find_best_k<MoveCircuit: Circuit<F>>(
        &self,
        circuit: &MoveCircuit,
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

    pub fn find_best_k_for_fast_circuit(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore,
    ) -> VmResult<u32> {
        let circuit = FastMoveCircuit::new(script, modules, args, data_store, self.loader());
        let public_inputs = vec![F::zero()];
        self.find_best_k(&circuit, vec![public_inputs])
    }

    pub fn generate_trace(
        &self,
        script: Vec<u8>,
        _modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore,
    ) -> VmResult<(Vec<ExecutionStep<F>>, Vec<RWOperation<F>>)> {
        let mut interp = Interpreter::<F>::new();
        let mut state = State::new(data_store);

        let (entry, arg_types) = self
            .loader()
            .load_script(&script, &mut state)
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

        Ok((exec_steps, rw_operations))
    }

    pub fn mock_prove_execution_trace(
        &self,
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecodes: BytecodeTable,
        k: u32,
    ) -> VmResult<()> {
        let circuit_inputs = CircuitInputs::new(exec_steps, rw_operations, bytecodes);
        debug!("{:?}", circuit_inputs);
        let circuit = VmCircuit { circuit_inputs };
        let prover = MockProver::run(k, &circuit, vec![]).map_err(|e| {
            debug!("Prover Error: {:?}", e);
            RuntimeError::new(StatusCode::ProofSystemError(e))
        })?;
        assert_eq!(prover.verify(), Ok(()));

        Ok(())
    }

    pub fn create_vm_circuit(
        &self,
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecodes: BytecodeTable,
    ) -> VmCircuit<F> {
        let circuit_inputs = CircuitInputs::new(exec_steps, rw_operations, bytecodes);
        VmCircuit { circuit_inputs }
    }

    pub fn mock_prove_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore,
        k: u32,
    ) -> VmResult<()> {
        let circuit = FastMoveCircuit::new(script, modules, args, data_store, self.loader());

        let public_inputs = vec![Fp::zero()];
        let prover = MockProver::<Fp>::run(k, &circuit, vec![public_inputs]).map_err(|e| {
            debug!("Prover Error: {:?}", e);
            RuntimeError::new(StatusCode::ProofSystemError(e))
        })?;
        assert_eq!(prover.verify(), Ok(()));
        Ok(())
    }

    pub fn setup_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        data_store: &mut StateStore,
        params: &Params<EqAffine>,
    ) -> VmResult<ProvingKey<EqAffine>> {
        let circuit = FastMoveCircuit::new(script, modules, None, data_store, self.loader());
        debug!("Generate vk");
        let vk = keygen_vk(params, &circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_vk should not fail".to_string())
        })?;
        debug!("Generate pk");
        let pk = keygen_pk(params, vk, &circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_pk should not fail".to_string())
        })?;
        Ok(pk)
    }

    pub fn prove_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        data_store: &mut StateStore,
        params: &Params<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let circuit = FastMoveCircuit::new(script, modules, args, data_store, self.loader());

        let public_inputs = vec![Fp::zero()];
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        let fast_prove_start = std::time::Instant::now();
        create_proof(
            params,
            &pk,
            &[circuit],
            &[&[public_inputs.as_slice()]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        info!("fast circuit proof size {} bytes", proof.len());
        let fast_prove_time = std::time::Instant::now().duration_since(fast_prove_start);
        info!(
            "fast circuit prove time: {} ms",
            fast_prove_time.as_millis()
        );

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let fast_verify_start = std::time::Instant::now();
        let result = verify_proof(
            params,
            pk.get_vk(),
            strategy,
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        );
        let fast_verify_time = std::time::Instant::now().duration_since(fast_verify_start);
        info!(
            "fast circuit verify time: {} ms",
            fast_verify_time.as_millis()
        );
        assert!(result.is_ok());
        Ok(())
    }

    pub fn setup_execution_trace(
        &self,
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecodes: BytecodeTable,
        params: &Params<EqAffine>,
    ) -> VmResult<ProvingKey<EqAffine>> {
        let circuit_inputs = CircuitInputs::new(exec_steps, rw_operations, bytecodes);
        let circuit = VmCircuit { circuit_inputs };
        debug!("Generate vk");
        let vk = keygen_vk(params, &circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_vk should not fail".to_string())
        })?;
        debug!("Generate pk");
        let pk = keygen_pk(params, vk, &circuit).map_err(|e| {
            RuntimeError::new(StatusCode::ProofSystemError(e))
                .with_message("keygen_pk should not fail".to_string())
        })?;
        Ok(pk)
    }

    pub fn prove_execution_trace(
        &self,
        exec_steps: Vec<ExecutionStep<F>>,
        rw_operations: Vec<RWOperation<F>>,
        bytecodes: BytecodeTable,
        params: &Params<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let circuit_inputs = CircuitInputs::new(exec_steps, rw_operations, bytecodes);
        let circuit = VmCircuit { circuit_inputs };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        let slow_prove_start = std::time::Instant::now();
        create_proof(params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        info!("vm circuit proof size {} bytes", proof.len());
        let slow_prove_time = std::time::Instant::now().duration_since(slow_prove_start);
        info!("vm circuit prove time: {} ms", slow_prove_time.as_millis());

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let slow_verify_start = std::time::Instant::now();
        let result = verify_proof(params, pk.get_vk(), strategy, &[&[]], &mut transcript);
        let slow_verify_time = std::time::Instant::now().duration_since(slow_verify_start);
        info!(
            "vm circuit verify time: {} ms",
            slow_verify_time.as_millis()
        );
        assert!(result.is_ok());
        Ok(())
    }
}

// impl<F: FieldExt> Default for Runtime<F>{
//     fn default() -> Self {
//         Self::new()
//     }
// }
