// Copyright (c) zkMove Authors

use crate::chips::execution_chip_v2::lookup_table::{FixedTableTag, LookupTableConfigV2};
use crate::chips::execution_chip_v2::ExecChipConfig;
use crate::utils::challenges::Challenges;
use crate::utils::{SubCircuit, SubCircuitConfig};
use crate::witness::WitnessV2;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use std::marker::PhantomData;
use strum::IntoEnumIterator;
use types::Field;

#[derive(Clone)]
pub struct VmCircuitConfig<F: Field> {
    lookup_table_config: LookupTableConfigV2<F>,
    exec_chip_config: ExecChipConfig<F>,
    fixed_table_tags: Vec<FixedTableTag>,
}

pub struct VmCircuitConfigArgs {
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> SubCircuitConfig<F> for VmCircuitConfig<F> {
    type ConfigArgs = VmCircuitConfigArgs;

    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self {
        let lookup_table_config = LookupTableConfigV2::new(meta);
        let exec_chip_config = ExecChipConfig::configure(meta, &lookup_table_config);
        // TODO: delete me
        #[cfg(test)]
        {
            use crate::utils::cell_manager::CellType;
            let mut headers = CellType::all()
                .iter()
                .map(|t| format!("{:?}", t))
                .collect::<Vec<_>>();
            headers.insert(0, "state".to_string());
            println!("{}", headers.join(","));

            for (state, stat) in &exec_chip_config.dynamic_cell_stat_map {
                let mut stat = CellType::all()
                    .iter()
                    .map(|t| stat.get(t).cloned().unwrap_or_default().to_string())
                    .collect::<Vec<_>>();
                stat.insert(0, format!("{:?}", state));
                println!("{}", stat.join(","));
            }
        }

        Self {
            fixed_table_tags: args.fixed_table_tags,
            exec_chip_config,
            lookup_table_config,
        }
    }
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: Field> {
    pub witness: WitnessV2,
    pub _maker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let fixed_table_tags = FixedTableTag::iter().collect();
        VmCircuitConfig::new(meta, VmCircuitConfigArgs { fixed_table_tags })
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.exec_chip_config.challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> SubCircuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;

    fn new_from_witness(witness: &WitnessV2) -> Self {
        Self {
            witness: witness.clone(),
            _maker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        VmCircuitConfig {
            exec_chip_config,
            lookup_table_config,
            fixed_table_tags,
        }: &Self::Config,
        challenges: &Challenges<halo2_proofs::circuit::Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        //dbg!(&self.witness.static_info.function_info);
        lookup_table_config.load(
            layouter,
            fixed_table_tags.clone(),
            &self.witness.static_info,
        )?;

        // Pads the witness to match `max_rows` in the circuit config.
        let padded_witness = self.witness.padding().unwrap_or_else(|| {
            panic!(
                "num of witness rows {} exceeds the max num of rows",
                self.witness.num_rows()
            )
        });
        exec_chip_config.assign(layouter, &padded_witness, challenges)?;
        Ok(())
    }
}

impl<F: Field> VmCircuit<F> {
    /// Return the minimum number of rows required to prove the circuit.
    pub fn circuit_height(&self) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = VmCircuit::<F>::configure(&mut cs);
        let table_rows = config
            .lookup_table_config
            .tables_height(&self.witness.static_info, config.fixed_table_tags);

        let witness_rows = if let Some(max_rows) = self.witness.circuit_config.max_rows {
            max_rows
        } else {
            self.witness.num_rows()
        };

        let rows_needed = vec![table_rows, witness_rows]
            .into_iter()
            .max()
            .unwrap_or(0);

        // halo2 prover requires 'usable_rows = n - (blinding_factors + 1)'
        rows_needed + (cs.blinding_factors() + 1)
    }
}
