use std::marker::PhantomData;

// Copyright (c) zkMove Authors
use crate::chips::execution_chip::{ExecutionChip, ExecutionChipConfig};
use crate::chips::memory_chip::{MemoryChip, MemoryChipConfig};
use crate::witness::Witness;
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;
use movelang::value::Value;
use snark_verifier_sdk::CircuitExt;
use types::Field;

#[derive(Clone)]
pub struct VmCircuitConfig<F: Field> {
    execution_chip_config: ExecutionChipConfig<F>,
    memory_chip_config: MemoryChipConfig<F>,
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub witness: Witness,
    pub public_input: Option<Value>,
    pub _maker: PhantomData<F>,
}

impl<F: Field> CircuitExt<F> for VmCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![vec![F::ZERO]]
    }
}

impl<F: Field> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        VmCircuitConfig {
            execution_chip_config: ExecutionChip::configure(meta),
            memory_chip_config: MemoryChip::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let execution_chip = ExecutionChip::<F>::construct(
            self.witness.clone(),
            self.public_input.clone(),
            config.execution_chip_config,
            (),
        );
        let (last_step_gc_cell_opt, stack_operations, locals_operations, global_operations) =
            execution_chip.assign(&mut layouter)?;

        let last_step_gc_cell = last_step_gc_cell_opt.ok_or_else(|| {
            error!("last step gc cell is None");
            Error::Synthesis
        })?;

        let memory_chip =
            MemoryChip::<F>::construct(self.witness.clone(), config.memory_chip_config, ());
        memory_chip.assign(
            &mut layouter,
            &self.witness.circuit_config,
            last_step_gc_cell,
            stack_operations,
            locals_operations,
            global_operations,
        )?;

        Ok(())
    }
}

impl<F: Field> VmCircuit<F> {
    pub fn circuit_height(&self) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = VmCircuit::<F>::configure(&mut cs);

        let execution_chip = ExecutionChip::<F>::construct(
            self.witness.clone(),
            self.public_input.clone(),
            config.execution_chip_config,
            (),
        );
        let memory_chip =
            MemoryChip::<F>::construct(self.witness.clone(), config.memory_chip_config, ());

        execution_chip.chip_height().max(memory_chip.chip_height())
    }
}
