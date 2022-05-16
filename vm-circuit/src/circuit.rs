// Copyright (c) zkMove Authors

use crate::chips::code_chips::{CodeChip, CodeChipConfig};
use crate::chips::execution_chips::{ExecutionChip, ExecutionChipConfig};
use crate::chips::memory_chips::{MemoryChip, MemoryChipConfig};
use crate::circuit_inputs::CircuitInputs;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone)]
pub struct VmCircuitConfig<F: FieldExt> {
    code_chip_config: CodeChipConfig<F>,
    execution_chip_config: ExecutionChipConfig<F>,
    memory_chip_config: MemoryChipConfig<F>,
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
}

impl<F: FieldExt> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        VmCircuitConfig {
            code_chip_config: CodeChip::configure(meta),
            execution_chip_config: ExecutionChip::configure(meta),
            memory_chip_config: MemoryChip::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let code_chip =
            CodeChip::<F>::construct(self.circuit_inputs.clone(), config.code_chip_config, ());
        code_chip.assign(&mut layouter)?;

        let execution_chip = ExecutionChip::<F>::construct(
            self.circuit_inputs.clone(),
            config.execution_chip_config,
            (),
        );
        execution_chip.assign(&mut layouter)?;

        let memory_chip =
            MemoryChip::<F>::construct(self.circuit_inputs.clone(), config.memory_chip_config, ());
        memory_chip.assign(&mut layouter)?;

        Ok(())
    }
}
