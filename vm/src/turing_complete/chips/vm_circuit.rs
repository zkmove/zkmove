// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::turing_complete::chips::step_chip::{StepChip, StepConfig};
use crate::turing_complete::circuit_inputs::CircuitInputs;
use halo2::circuit::Region;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone)]
pub struct VmCircuitConfig<F: FieldExt> {
    step_config: StepConfig<F>,
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
        let s_vm = meta.complex_selector();
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());
        let step_config = StepChip::configure(meta, advices);

        Self::Config { step_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let step_chip = StepChip::<F>::construct(config.step_config, ());

        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &self.circuit_inputs.exec_steps {
                    step_chip.config.s_step.enable(&mut region, offset)?;
                    step_chip.assign(
                        &mut region,
                        offset,
                        step,
                        &self.circuit_inputs.rw_lookup_table,
                    )?;

                    offset += STEP_HEIGHT;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
