// Copyright (c) zkMove Authors

use crate::circuit::{EvaluationChip, EvaluationConfig};
use crate::interpreter::Interpreter;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::state::StateStore;

#[derive(Clone)]
pub struct FastMoveCircuit<'a> {
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    loader: &'a MoveLoader,
}

impl<'a> FastMoveCircuit<'a> {
    pub fn new(
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        loader: &'a MoveLoader,
    ) -> Self {
        FastMoveCircuit {
            script,
            modules,
            args,
            loader,
        }
    }

    pub fn loader(&self) -> &'a MoveLoader {
        &self.loader
    }
}

impl<F: FieldExt> Circuit<F> for FastMoveCircuit<'_> {
    type Config = EvaluationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            script: self.script.clone(),
            modules: self.modules.clone(),
            args: None,
            loader: self.loader(),
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
        for module in self.modules.clone().into_iter() {
            state.add_module(module);
        }
        let mut interp = Interpreter::new();

        let (entry, arg_types) = self
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
                self.loader(),
            )
            .map_err(|e| {
                error!("run script failed: {:?}", e);
                Error::SynthesisError
            })?;

        // evaluation_chip.expose_public(layouter.namespace(|| "expose state root"), state_root, 0)?;

        Ok(())
    }
}
