pub mod circuit;
pub mod frame;
pub mod instructions;
pub mod interpreter;
pub mod plonk;
pub mod runtime;
pub mod stack;
pub mod value;

use crate::circuit::{EvaluationChip, EvaluationConfig};
use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2::{dev::MockProver, pasta::Fp};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::state::StateStore;

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
    type Config = EvaluationConfig;
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

        EvaluationChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let evaluation_chip = EvaluationChip::<F>::construct(config, ());
        let mut state = StateStore::new();
        // let state_root = evaluation_chip.load_private(layouter.namespace(|| "load state root"), Some(F::zero()))?;
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
            .run_script(
                &evaluation_chip,
                layouter.namespace(|| "run script"),
                entry,
                self.args.clone(),
                arg_types,
                runtime.loader(),
            )
            .map_err(|e| {
                error!("run script failed: {:?}", e);
                Error::SynthesisError
            })?;

        // evaluation_chip.expose_public(layouter.namespace(|| "expose state root"), state_root, 0)?;

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

pub fn prove_script(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    k: u32,
) -> VmResult<()> {
    let circuit = FastMoveCircuit {
        script,
        modules,
        args,
    };

    let public_inputs = vec![Fp::zero()];
    let prover = MockProver::<Fp>::run(k, &circuit, vec![public_inputs]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    assert_eq!(prover.verify(), Ok(()));
    Ok(())
}

// pub fn verify_script<E: Engine>(key: &VerifyingKey<E>, proof: &Proof<E>) -> VmResult<bool> {
//     let pvk = groth16::prepare_verifying_key(&key);
//     let public_input = Vec::new();
//     groth16::verify_proof(&pvk, proof, &public_input)
//         .map_err(|e| RuntimeError::new(StatusCode::SynthesisError(e)))
// }
