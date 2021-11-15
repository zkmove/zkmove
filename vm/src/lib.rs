pub mod circuit;
pub mod frame;
pub mod instructions;
pub mod interpreter;
pub mod plonk;
pub mod runtime;
pub mod stack;
pub mod value;

use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use crate::circuit::{InstructionsConfig, InstructionsChip};
use crypto::constraint_system::DummyCS;
use error::{RuntimeError, StatusCode, VmResult};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::state::StateStore;
use rand::ThreadRng;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use std::marker::PhantomData;

pub struct FastMoveCircuit {
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
}

impl FastMoveCircuit {
    pub fn new(
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
    ) -> Self {
        FastMoveCircuit {
            script,
            modules,
            args,
        }
    }
}

impl<F: FieldExt> Circuit<F> for FastMoveCircuit {
    type Config = InstructionsConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            script: self.script.clone(),
            modules: self.modules.clone(),
            args: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        InstructionsChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let instructions_chip = InstructionsChip::<F>::construct(config, ());
        let mut state = StateStore::new();
        let runtime = Runtime::new();
        for module in self.modules.clone().into_iter() {
            state.add_module(module);
        }
        let mut interp = Interpreter::new();

        let (entry, arg_types) = runtime
            .loader()
            .load_script(&self.script, &mut state)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                Error::SynthesisError
            })?;
        debug!("script entry {:?}", entry.name());

        interp
            .run_script(&instructions_chip, layouter.namespace(|| "run script"), entry, self.args.clone(), arg_types, runtime.loader())
            .map_err(|e| {
                error!("run script failed: {:?}", e);
                Error::SynthesisError
            })?;

        Ok(())
    }
}

// pub fn execute_script(
//     script: Vec<u8>,
//     modules: Vec<CompiledModule>,
//     args: Option<ScriptArguments>,
// ) -> VmResult<()> {
//     let mut state = StateStore::new();
//     let runtime = Runtime::new();
//     for module in modules.into_iter() {
//         state.add_module(module);
//     }
//     let mut cs = DummyCS::<Bn256>::new();
//     let mut interp = Interpreter::new();
//
//     let (entry, arg_types) = runtime
//         .loader()
//         .load_script(&script, &mut state)
//         .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))?;
//     debug!("script entry {:?}", entry.name());
//
//     interp.run_script(&mut cs, entry, args, arg_types, runtime.loader())
// }

// pub fn setup_script<E: Engine>(
//     script: Vec<u8>,
//     modules: Vec<CompiledModule>,
// ) -> VmResult<Parameters<E>> {
//     let rng = &mut rand::thread_rng();
//     let circuit = MoveCircuit {
//         script,
//         modules,
//         args: None,
//     };
//
//     groth16::generate_random_parameters::<E, MoveCircuit, ThreadRng>(circuit, rng)
//         .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
// }

// pub fn prove_script<E: Engine>(
//     script: Vec<u8>,
//     modules: Vec<CompiledModule>,
//     args: Option<ScriptArguments>,
//     params: &Parameters<E>,
// ) -> VmResult<Proof<E>> {
//     let rng = &mut rand::thread_rng();
//
//     let circuit = MoveCircuit {
//         script,
//         modules,
//         args,
//     };
//
//     groth16::create_random_proof(circuit, params, rng)
//         .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
// }

// pub fn verify_script<E: Engine>(key: &VerifyingKey<E>, proof: &Proof<E>) -> VmResult<bool> {
//     let pvk = groth16::prepare_verifying_key(&key);
//     let public_input = Vec::new();
//     groth16::verify_proof(&pvk, proof, &public_input)
//         .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
// }
