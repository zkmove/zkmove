// Copyright (c) zkMove Authors

use halo2_poseidon::primitives::{ConstantLength, Spec};
use halo2_poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use std::convert::TryInto;
use std::marker::PhantomData;
use types::Field;

/// A wrapper for halo2 poseidon Pow5Chip.

#[derive(Clone)]
pub struct PoseidonConfig<F: Field, const WIDTH: usize, const RATE: usize> {
    inputs: [Column<Advice>; WIDTH],
    pow5_config: Pow5Config<F, WIDTH, RATE>,
}

#[derive(Clone)]
pub struct PoseidonChip<
    F: Field,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<F, WIDTH, RATE>,
    _spec: PhantomData<S>,
}

impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<F, S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<F, WIDTH, RATE>) -> Self {
        Self {
            config,
            _spec: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonConfig<F, WIDTH, RATE> {
        let state = [(); WIDTH].map(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();

        let rc_a = [(); WIDTH].map(|_| meta.fixed_column());
        let rc_b = [(); WIDTH].map(|_| meta.fixed_column());

        meta.enable_constant(rc_b[0]);
        state
            .iter()
            .for_each(|column| meta.enable_equality(*column));

        let pow5_config = Pow5Chip::configure::<S>(meta, state, partial_sbox, rc_a, rc_b);

        PoseidonConfig {
            pow5_config,
            inputs: state,
        }
    }

    pub fn hash(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        let inputs = layouter.assign_region(
            || "load inputs",
            |mut region| {
                let result = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, input)| {
                        input.copy_advice(
                            || format!("input {}", i),
                            &mut region,
                            self.config.inputs[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<F, F>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "init"),
        )?;

        hasher.hash(layouter.namespace(|| "hash"), inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::{PoseidonChip, PoseidonConfig};
    use crypto::poseidon::{FieldHasher, Poseidon, SmtP128Pow5T3};
    use halo2_poseidon::primitives::Spec;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use std::convert::TryInto;
    use std::marker::PhantomData;
    use types::Field;

    #[derive(Clone)]
    struct TestConfig<F: Field, const WIDTH: usize, const RATE: usize, const L: usize> {
        poseidon_config: PoseidonConfig<F, WIDTH, RATE>,
        inputs: [Column<Advice>; L],
        output: Column<Advice>,
    }

    struct TestCircuit<
        F: Field,
        S: Spec<F, WIDTH, RATE>,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > {
        inputs: [Value; L],
        output: Value,
        _spec: PhantomData<S>,
    }

    impl<
            F: Field,
            S: Spec<F, WIDTH, RATE>,
            const WIDTH: usize,
            const RATE: usize,
            const L: usize,
        > Circuit<F> for TestCircuit<F, S, WIDTH, RATE, L>
    {
        type Config = TestConfig<F, WIDTH, RATE, L>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                inputs: [Value::default(); L],
                output: Value::default(),
                _spec: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let inputs = [(); L].map(|_| meta.advice_column());
            let output = meta.advice_column();

            inputs
                .iter()
                .for_each(|column| meta.enable_equality(*column));
            meta.enable_equality(output);

            TestConfig {
                poseidon_config: PoseidonChip::<F, S, WIDTH, RATE, L>::configure(meta),
                inputs,
                output,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let assigned_inputs = layouter.assign_region(
                || "assign inputs",
                |mut region| -> Result<[AssignedCell<F, F>; L], Error> {
                    let result = self
                        .inputs
                        .iter()
                        .enumerate()
                        .map(|(i, input)| {
                            region.assign_advice(
                                || format!("input {}", i),
                                config.inputs[i],
                                0,
                                || *input,
                            )
                        })
                        .collect::<Result<Vec<AssignedCell<F, F>>, Error>>();
                    Ok(result?.try_into().unwrap())
                },
            )?;

            let chip =
                PoseidonChip::<F, S, WIDTH, RATE, L>::construct(config.poseidon_config.clone());
            let output = chip.hash(&mut layouter.namespace(|| "hash"), &assigned_inputs)?;

            layouter.assign_region(
                || "constrain output",
                |mut region| {
                    let expected_var =
                        region.assign_advice(|| "load output", config.output, 0, || self.output)?;
                    region.constrain_equal(output.cell(), expected_var.cell())
                },
            )
        }
    }

    #[test]
    fn test_poseidon_chip() {
        // Circuit is very small, we pick a small value here
        let k = 10;

        let a = Fp::from(3);
        let b = Fp::from(2);
        let poseidon = Poseidon::<Fp, 2>::new();
        let c = poseidon.hash([a, b]).unwrap();
        let wrong_c = Fp::from(4);

        let circuit = TestCircuit::<Fp, SmtP128Pow5T3<Fp, 0>, 3, 2, 2> {
            inputs: [Value::known(a), Value::known(b)],
            output: Value::known(c),
            _spec: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // If use some other output, the proof will fail
        let circuit = TestCircuit::<Fp, SmtP128Pow5T3<Fp, 0>, 3, 2, 2> {
            inputs: [Value::known(a), Value::known(b)],
            output: Value::known(wrong_c),
            _spec: PhantomData,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
