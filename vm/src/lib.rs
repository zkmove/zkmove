pub mod chips;
pub mod circuit;
pub mod frame;
pub mod instructions;
pub mod interpreter;
pub mod runtime;
pub mod stack;
pub mod value;

use crate::circuit::{EvaluationChip, EvaluationConfig};
use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey};
use halo2::poly::commitment::Params;
use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2::{dev::MockProver, pasta::EqAffine, pasta::Fp};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::state::StateStore;

#[derive(Clone)]
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
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
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

        // condition is true by default
        interp.conditions().push(F::one()).map_err(|e| {
            error!("set condition failed: {:?}", e);
            Error::SynthesisError
        })?;

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

pub fn mock_prove_script(
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

pub fn setup_script(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    params: &Params<EqAffine>,
) -> VmResult<ProvingKey<EqAffine>> {
    let circuit = FastMoveCircuit {
        script,
        modules,
        args: None,
    };
    debug!("Generate vk");
    let vk = keygen_vk(params, &circuit).map_err(|_| {
        RuntimeError::new(StatusCode::SynthesisError)
            .with_message("keygen_vk should not fail".to_string())
    })?;
    debug!("Generate pk");
    let pk = keygen_pk(params, vk, &circuit).map_err(|_| {
        RuntimeError::new(StatusCode::SynthesisError)
            .with_message("keygen_pk should not fail".to_string())
    })?;
    Ok(pk)
}

pub fn prove_script(
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    params: &Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
) -> VmResult<()> {
    let circuit = FastMoveCircuit {
        script,
        modules,
        args,
    };

    let public_inputs = vec![Fp::zero()];
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    create_proof(
        params,
        &pk,
        &[circuit.clone()],
        &[&[public_inputs.as_slice()]],
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();

    let msm = params.empty_msm();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let guard = verify_proof(
        params,
        pk.get_vk(),
        msm,
        &[&[public_inputs.as_slice()]],
        &mut transcript,
    )
    .unwrap();
    let msm = guard.clone().use_challenges();
    assert!(msm.eval());
    Ok(())
}
