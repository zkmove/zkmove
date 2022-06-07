// Copyright (c) zkMove Authors

use crate::evaluation_chip::{EvaluationChip, EvaluationConfig};
use crate::interpreter::Interpreter;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;
use move_binary_format::file_format::CompiledScript;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::state::StateStore;

#[derive(Clone)]
pub struct MoveCircuit<'l> {
    script: CompiledScript,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    state: StateStore,
    loader: &'l MoveLoader,
}

impl<'l> MoveCircuit<'l> {
    pub fn new(
        script: CompiledScript,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        state_store: StateStore,
        loader: &'l MoveLoader,
    ) -> Self {
        MoveCircuit {
            script,
            modules,
            args,
            state: state_store,
            loader,
        }
    }

    pub fn loader(&self) -> &'l MoveLoader {
        &self.loader
    }

    pub fn state(&self) -> &StateStore {
        &self.state
    }
}

impl<'l, F: FieldExt> Circuit<F> for MoveCircuit<'l> {
    type Config = EvaluationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            script: self.script.clone(),
            modules: self.modules.clone(),
            args: None,
            state: self.state.clone(),
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
        // let state_root = evaluation_chip.load_private(layouter.namespace(|| "load state root"), Some(F::zero()))?;
        let mut interp = Interpreter::new();

        let mut script_bytes = vec![];
        self.script.serialize(&mut script_bytes).map_err(|e| {
            error!("serialize script failed: {:?}", e);
            Error::Synthesis
        })?;

        let (entry, arg_types) = self
            .loader()
            .load_script(&script_bytes, &self.state)
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                Error::Synthesis
            })?;
        trace!("script entry {:?}", entry.name());

        // condition is true by default
        interp.conditions().push(F::one()).map_err(|e| {
            error!("set condition failed: {:?}", e);
            Error::Synthesis
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
                let error: Error = e.into();
                error
            })?;

        // evaluation_chip.expose_public(layouter.namespace(|| "expose state root"), state_root, 0)?;

        Ok(())
    }
}
