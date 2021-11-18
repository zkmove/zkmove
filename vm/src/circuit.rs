use crate::instructions::{AddInstruction, EqInstruction, Instructions};
use crate::plonk::add::{AddChip, AddConfig};
use crate::plonk::eq::{EqChip, EqConfig};
use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
};
use movelang::value::MoveValueType;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct EvaluationConfig {
    advice: [Column<Advice>; 2],

    // Public inputs
    instance: Column<Instance>,

    // Fixed column to load constants
    constant: Column<Fixed>,

    add_config: AddConfig,
    eq_config: EqConfig,
}

pub struct EvaluationChip<F: FieldExt> {
    config: EvaluationConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AddInstruction<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error> {
        let config = self.config().add_config.clone();

        let add_chip = AddChip::<F>::construct(config, ());
        add_chip.add(layouter, a, b)
    }
}

impl<F: FieldExt> EqInstruction<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn eq(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error> {
        let config = self.config().eq_config.clone();

        let eq_chip = EqChip::<F>::construct(config, ());
        eq_chip.eq(layouter, a, b)
    }
}

impl<F: FieldExt> Chip<F> for EvaluationChip<F> {
    type Config = EvaluationConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> EvaluationChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        let add_config = AddChip::configure(meta, advice);
        let eq_config = EqChip::configure(meta, advice);

        meta.enable_equality(instance.into());
        meta.enable_constant(constant);

        EvaluationConfig {
            advice,
            instance,
            constant,
            add_config,
            eq_config,
            //other config
        }
    }
}

impl<F: FieldExt> Instructions<F> for EvaluationChip<F> {
    type Value = Value<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error> {
        let config = self.config();

        let mut alloc = None;
        layouter.assign_region(
            || "load private",
            |mut region| {
                let cell = region.assign_advice(
                    || "private input",
                    config.advice[0],
                    0,
                    || value.ok_or(Error::SynthesisError),
                )?;
                alloc = Some(
                    Value::new_variable(value, Some(cell), ty.clone())
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;
        Ok(alloc.unwrap())
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error> {
        let config = self.config();

        let mut alloc = None;
        layouter.assign_region(
            || "load constant",
            |mut region| {
                let cell = region.assign_fixed(
                    || "constant value",
                    config.constant,
                    0,
                    || Ok(constant),
                )?;
                alloc = Some(
                    Value::new_constant(constant, Some(cell), ty.clone())
                        .map_err(|_| Error::SynthesisError)?,
                );

                Ok(())
            },
        )?;
        Ok(alloc.unwrap())
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        value: <Self as Instructions<F>>::Value,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(value.cell().unwrap(), config.instance, row)
    }
}

struct TestCircuit<F: FieldExt> {
    a: Option<F>,
    a_type: MoveValueType,
    b: Option<F>,
    b_type: MoveValueType,
}

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
    type Config = EvaluationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: None,
            a_type: MoveValueType::U8,
            b: None,
            b_type: MoveValueType::U8,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        EvaluationChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let evaluation_chip = EvaluationChip::<F>::construct(config, ());

        let a = evaluation_chip.load_private(
            layouter.namespace(|| "load a"),
            self.a,
            self.a_type.clone(),
        )?;
        let b = evaluation_chip.load_private(
            layouter.namespace(|| "load b"),
            self.b,
            self.b_type.clone(),
        )?;
        let c = evaluation_chip.add(layouter.namespace(|| "a + b"), a.clone(), b.clone())?;
        let d = evaluation_chip.eq(layouter.namespace(|| "a == b"), a, b)?;

        evaluation_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)?;
        evaluation_chip.expose_public(layouter.namespace(|| "expose d"), d, 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::TestCircuit;
    use halo2::{dev::MockProver, pasta::Fp};
    use movelang::value::MoveValueType;

    #[test]
    fn test_evaluation() {
        // Circuit is very small, we pick a small value here
        let k = 4;

        // Prepare the private and public inputs to the circuit
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = a + b;
        let d = Fp::zero();

        // Instantiate the circuit with the private inputs
        let circuit = TestCircuit {
            a: Some(a),
            a_type: MoveValueType::U8,
            b: Some(b),
            b_type: MoveValueType::U8,
        };

        let mut public_inputs = vec![c, d];

        // Given the correct public input, circuit will verify
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // If use some other public input, the proof will fail
        public_inputs[1] = Fp::one();
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }
}
