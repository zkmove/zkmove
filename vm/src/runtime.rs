use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::interpreter::Interpreter;
use bellman::pairing::bn256::Bn256;
use bellman::groth16;
use bellman::pairing::Engine;
use bellman::groth16::{Parameters, Proof, VerifyingKey};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use crypto::constraint_system::DummyCS;
use logger::prelude::*;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use move_core_types::value::MoveValue;
use rand::ThreadRng;

struct MoveCircuit {
    script: Vec<u8>,
    args: ScriptArguments,
}

impl<E: Engine> Circuit<E> for MoveCircuit {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS,
    ) -> std::result::Result<(), SynthesisError> {
        let runtime = Runtime::new();
        let mut interp = Interpreter::new();

        let entry = runtime
            .loader()
            .load_script(&self.script)
            .map_err(|_| SynthesisError::AssignmentMissing)?; //fixme
        debug!("script entry {:?}", entry.name());

        interp.run_script(cs, entry, self.args);
        Ok(())
    }
}

pub struct Runtime {
    loader: MoveLoader,
}

impl Runtime {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new(),
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }

    pub fn execute_script(&self, script: Vec<u8>, args: ScriptArguments) -> VmResult<()> {
        let mut cs = DummyCS::<Bn256>::new();
        let mut interp = Interpreter::new();

        let entry = self
            .loader
            .load_script(&script)
            .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))?;
        debug!("script entry {:?}", entry.name());

        interp.run_script(&mut cs, entry, args)
    }

    pub fn setup_script<E: Engine>(&self, script: Vec<u8>) -> VmResult<Parameters<E>> {
        let rng = &mut rand::thread_rng();
        let circuit = MoveCircuit {
            script,
            args: ScriptArguments::new(vec![]),
        };

        groth16::generate_random_parameters::<E, MoveCircuit, ThreadRng>(circuit, rng).map_err(
            |e| RuntimeError::new(StatusCode::SynthesisError)
        )
    }
}
