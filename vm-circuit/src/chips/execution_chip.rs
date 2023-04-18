// Copyright (c) zkMove Authors

use crate::witness::Witness;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use step_chip::{StepChip, StepConfig};
use step_chip::STEP_HEIGHT;

pub mod utils;
pub mod instructions;
pub mod lookup_tables;
pub mod opcode;
pub mod param;
pub mod step_chip;

#[derive(Clone, Debug)]
pub struct ExecutionChipConfig<F: FieldExt> {
    pub(crate) step_config: StepConfig<F>,
}

#[derive(Clone, Debug)]
pub struct ExecutionChip<F: FieldExt> {
    pub(crate) witness: Witness<F>,
    pub(crate) config: ExecutionChipConfig<F>,
}

impl<F: FieldExt> Chip<F> for ExecutionChip<F> {
    type Config = ExecutionChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ExecutionChip<F> {
    pub fn construct(
        witness: Witness<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self { witness, config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        let step_config = StepChip::configure(meta);

        ExecutionChipConfig {
            step_config,
        }
    }

    // return assigned cells for 1.last_step_gc, 2.sorted_stack_ops, 3.sorted_locals_ops
    // 4. sorted_global_ops
    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Option<AssignedCell<F, F>>, Error> {
        let step_chip = StepChip::<F>::construct(self.config.step_config.clone(), ());
        let exec_steps = self.witness.process_exec_steps()?;
        let mut gc_cell = None;
        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &exec_steps {
                    step_chip.config.s_step.enable(&mut region, offset)?;
                    gc_cell =
                        step_chip.assign(&mut region, offset, step, &self.witness.rw_operations)?;

                    offset += STEP_HEIGHT;
                }
                Ok(())
            },
        )?;
        let last_step_gc_cell = gc_cell;

        Ok(last_step_gc_cell)
    }
}
