// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::ExecChipConfig;
use crate::witness::WitnessV2;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use movelang::value::Value;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone)]
pub struct VmCircuitConfig<F: Field> {
    exec_chip_config: ExecChipConfig<F>,
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub witness: WitnessV2,
    pub public_input: Option<Value>,
    pub _maker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        VmCircuitConfig {
            exec_chip_config: ExecChipConfig::configure(meta),
        }
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        mut _layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
