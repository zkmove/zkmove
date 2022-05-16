// Copyright (c) zkMove Authors

use crate::chips::code_chips::bytecode_chip::{BytecodeChip, BytecodeChipConfig};
use crate::circuit_inputs::CircuitInputs;
use bytecode_chip::BYTECODE_CHIP_WIDTH;
use halo2_proofs::circuit::{Chip, Region};
use halo2_proofs::plonk::{Advice, Column};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};

pub mod bytecode_chip;

#[derive(Clone, Debug)]
pub struct CodeChipConfig<F: FieldExt> {
    advices: [Column<Advice>; BYTECODE_CHIP_WIDTH],
    bytecode_chip_config: BytecodeChipConfig<F>,
}

#[derive(Clone, Debug)]
pub struct CodeChip<F: FieldExt> {
    pub circuit_inputs: CircuitInputs<F>,
    pub config: CodeChipConfig<F>,
}

impl<F: FieldExt> Chip<F> for CodeChip<F> {
    type Config = CodeChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> CodeChip<F> {
    pub fn construct(
        circuit_inputs: CircuitInputs<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            circuit_inputs,
            config,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        let advices = [(); BYTECODE_CHIP_WIDTH].map(|_| meta.advice_column());
        let bytecode_chip_config = BytecodeChip::configure(meta, advices);

        // todo: create gate for code hash check

        CodeChipConfig {
            advices,
            bytecode_chip_config,
        }
    }

    pub fn assign(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let bytecode_chip =
            BytecodeChip::<F>::construct(self.config.bytecode_chip_config.clone(), ());
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
