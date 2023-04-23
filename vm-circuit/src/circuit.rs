// Copyright (c) zkMove Authors
use crate::chips::execution_chip::lookup_tables::{LookupTableConfig, LookupsWithCondition};
use crate::chips::execution_chip::{ExecutionChip, ExecutionChipConfig};
use crate::chips::memory_chip::{MemoryChip, MemoryChipConfig};
use crate::witness::Witness;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use logger::prelude::*;

#[derive(Clone)]
pub struct VmCircuitConfig<F: FieldExt> {
    pub execution_chip_config: ExecutionChipConfig<F>,
    lookup_table: LookupTableConfig<F>,
    memory_chip_config: MemoryChipConfig<F>,
}

#[derive(Clone, Default)]
pub struct VmCircuit<F: FieldExt> {
    pub witness: Witness<F>,
}

impl<F: FieldExt> Circuit<F> for VmCircuit<F> {
    type Config = VmCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let mut lookups = LookupsWithCondition::new();
        let execution_chip_config = ExecutionChip::configure(meta, &mut lookups);
        let s_step = execution_chip_config.s_step;
        let lookup_table = LookupTableConfig::configure(meta, &lookups, s_step);
        VmCircuitConfig {
            execution_chip_config,
            lookup_table,
            memory_chip_config: MemoryChip::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let execution_chip =
            ExecutionChip::<F>::construct(self.witness.clone(), config.execution_chip_config, ());
        let last_step_gc_cell_opt = execution_chip.assign(&mut layouter)?;

        let (stack_operations, locals_operations, global_operations) =
            LookupTableConfig::assign(&mut layouter, &execution_chip, &config.lookup_table)?;
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
