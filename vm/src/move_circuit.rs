// Copyright (c) zkMove Authors

use crate::evaluation_chip::{EvaluationChip, EvaluationConfig};
use crate::interpreter::Interpreter;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;
use movelang::state::{State, StateStore};

#[derive(Clone)]
pub struct FastMoveCircuit<'l, 's> {
    script: Vec<u8>,
    modules: Vec<CompiledModule>,
    args: Option<ScriptArguments>,
    state: State<'s>,
    loader: &'l MoveLoader,
}

impl<'l, 's> FastMoveCircuit<'l, 's> {
    pub fn new(
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        state_store: &'s mut StateStore,
        loader: &'l MoveLoader,
    ) -> Self {
        FastMoveCircuit {
            script,
            modules,
            args,
            state: State::new(state_store),
            loader,
        }
    }

    pub fn loader(&self) -> &'l MoveLoader {
        &self.loader
    }

    pub fn state(&self) -> &'s State {
        &self.state
    }
}

impl<'l, 's, F: FieldExt> Circuit<F> for FastMoveCircuit<'l, 's> {
    type Config = EvaluationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            script: self.script.clone(),
            modules: self.modules.clone(),
            args: None,
            state: State::new(self.state.state_store),
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

        let (entry, arg_types) = self
            .loader()
            .load_script(&self.script, &mut self.state.clone())
            .map_err(|e| {
                error!("load script failed: {:?}", e);
                Error::Synthesis
            })?;
        debug!("script entry {:?}", entry.name());

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
                error!("run script failed: {:?}", e);
                Error::Synthesis
            })?;

        // evaluation_chip.expose_public(layouter.namespace(|| "expose state root"), state_root, 0)?;

        Ok(())
    }
}
