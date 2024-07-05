// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::LookupTableConfigV2;
use crate::chips::execution_chip_v2::ExecChipConfig;
use crate::utils::challenges::Challenges;
use crate::utils::{SubCircuit, SubCircuitConfig};
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

pub struct VmCircuitConfigArgs {
    challenges: Challenges,
}

impl<F: Field> SubCircuitConfig<F> for VmCircuitConfig<F> {
    type ConfigArgs = VmCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let lookup_tables = LookupTableConfigV2::new(meta);
        let challenges_expr = args.challenges.exprs(meta);
        let exec_chip_config =
            ExecChipConfig::configure(meta, challenges_expr.clone(), lookup_tables);
        Self { exec_chip_config }
    }
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub witness: WitnessV2,
    pub public_input: Option<Value>,
    pub _maker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for VmCircuit<F> {
    type Config = (VmCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        (
            VmCircuitConfig::new(meta, VmCircuitConfigArgs { challenges }),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> SubCircuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;

    fn new_from_witness(witness: &WitnessV2) -> Self {
        Self {
            witness: witness.clone(),
            public_input: None,
            _maker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        VmCircuitConfig { exec_chip_config }: &Self::Config,
        challenges: &Challenges<halo2_proofs::circuit::Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        // TODO: load tables
        exec_chip_config.assign(layouter, &self.witness, challenges)?;
        Ok(())
    }

    fn min_num_rows(witness: &WitnessV2) -> (usize, usize) {
        todo!()
    }
}
