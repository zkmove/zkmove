// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::bytecode_chip::{
    BytecodeChip, BytecodeChipConfig, BYTECODE_CHIP_WIDTH,
};
use crate::vm_circuit::circuit_inputs::CircuitInputs;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Advice, Column};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[derive(Clone)]
pub struct BytecodeCircuitConfig<F: FieldExt> {
    advices: [Column<Advice>; BYTECODE_CHIP_WIDTH],
    bytecode_chip_config: BytecodeChipConfig<F>,
}

#[derive(Clone, Default)]
pub struct BytecodeCircuit<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
}

impl<F: FieldExt> Circuit<F> for BytecodeCircuit<F> {
    type Config = BytecodeCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advices = [(); BYTECODE_CHIP_WIDTH].map(|_| meta.advice_column());
        let bytecode_chip_config = BytecodeChip::configure(meta, advices);

        // todo: create gate for code hash check

        BytecodeCircuitConfig {
            advices,
            bytecode_chip_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let bytecode_chip = BytecodeChip::<F>::construct(config.bytecode_chip_config.clone(), ());
        let bytecodes = self.circuit_inputs.bytecode_table.as_inner();
        let mut code_hash = None;

        layouter.assign_region(
            || "bytecodes",
            |mut region: Region<'_, F>| {
                for (index, bytecode) in bytecodes.iter().enumerate() {
                    let hash = if index == 0 {
                        bytecode_chip
                            .config
                            .s_first_bytecode
                            .enable(&mut region, index)?;
                        bytecode_chip.assign(
                            &mut region,
                            index,
                            bytecode,
                            F::zero(), /* fixme */
                        )?
                    } else {
                        bytecode_chip.config.s_bytecode.enable(&mut region, index)?;
                        bytecode_chip.assign(
                            &mut region,
                            index,
                            bytecode,
                            F::zero(), /* fixme */
                        )?
                    };
                    if index == bytecodes.len() - 1 {
                        code_hash = Some(hash);
                    }
                }
                Ok(())
            },
        )?;

        // todo: assign region for code hash check

        Ok(())
    }
}
