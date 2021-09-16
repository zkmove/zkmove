pub mod frame;
pub mod gadgets;
pub mod interpreter;
pub mod runtime;
pub mod stack;
pub mod value;

use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use bellman::groth16;
use bellman::groth16::{Parameters, Proof, VerifyingKey};
use bellman::pairing::bn256::Bn256;
use bellman::pairing::Engine;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use crypto::constraint_system::DummyCS;
use error::{RuntimeError, StatusCode, VmResult};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::state::StateStore;
use rand::ThreadRng;

pub struct MoveCircuit {
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
}

impl MoveCircuit {
    pub fn new(
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
    ) -> Self {
        MoveCircuit {
            script,
            modules,
            args,
        }
    }
}

impl<E: Engine> Circuit<E> for MoveCircuit {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> std::result::Result<(), SynthesisError> {
        let mut state = StateStore::new();
        let runtime = Runtime::new();
        for module in self.modules.into_iter() {
            state.add_module(module);
        }
        let mut interp = Interpreter::new();

        let (entry, arg_types) = runtime
            .loader()
            .load_script(&self.script, &mut state)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                // Fixme: there is no matching error
                SynthesisError::AssignmentMissing
            })?;
        debug!("script entry {:?}", entry.name());

        interp
            .run_script(cs, entry, self.args, arg_types, runtime.loader())
            .map_err(|e| {
                error!("run script failed: {:?}", e);
                // Fixme: there is no matching error
                SynthesisError::AssignmentMissing
            })?;

        Ok(())
    }
}

pub fn execute_script(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
) -> VmResult<()> {
    let mut state = StateStore::new();
    let runtime = Runtime::new();
    for module in modules.into_iter() {
        state.add_module(module);
    }
    let mut cs = DummyCS::<Bn256>::new();
    let mut interp = Interpreter::new();

    let (entry, arg_types) = runtime
        .loader()
        .load_script(&script, &mut state)
        .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))?;
    debug!("script entry {:?}", entry.name());

    interp.run_script(&mut cs, entry, args, arg_types, runtime.loader())
}

pub fn setup_script<E: Engine>(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
) -> VmResult<Parameters<E>> {
    let rng = &mut rand::thread_rng();
    let circuit = MoveCircuit {
        script,
        modules,
        args: None,
    };

    groth16::generate_random_parameters::<E, MoveCircuit, ThreadRng>(circuit, rng)
        .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
}

pub fn prove_script<E: Engine>(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    params: &Parameters<E>,
) -> VmResult<Proof<E>> {
    let rng = &mut rand::thread_rng();

    let circuit = MoveCircuit {
        script,
        modules,
        args,
    };

    groth16::create_random_proof(circuit, params, rng)
        .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
}

pub fn verify_script<E: Engine>(key: &VerifyingKey<E>, proof: &Proof<E>) -> VmResult<bool> {
    let pvk = groth16::prepare_verifying_key(&key);
    let public_input = Vec::new();
    groth16::verify_proof(&pvk, proof, &public_input)
        .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
}
