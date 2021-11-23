use crate::chips::arithmetic::{ArithmeticChip, ArithmeticConfig};
use crate::chips::logical::{LogicalChip, LogicalConfig};
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
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
    advice: [Column<Advice>; 4],

    // Public inputs
    instance: Column<Instance>,

    // Fixed column to load constants
    constant: Column<Fixed>,

    arithmetic_config: ArithmeticConfig,
    logical_config: LogicalConfig,
}

pub struct EvaluationChip<F: FieldExt> {
    config: EvaluationConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithmeticInstructions<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.add(layouter, a, b, cond)
    }

    fn sub(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.sub(layouter, a, b, cond)
    }

    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.mul(layouter, a, b, cond)
    }
}

impl<F: FieldExt> LogicalInstructions<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn eq(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.eq(layouter, a, b, cond)
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
        advice: [Column<Advice>; 4],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        let arithmetic_config = ArithmeticChip::configure(meta, advice);
        let logical_config = LogicalChip::configure(meta, advice);

        meta.enable_equality(instance.into());
        meta.enable_constant(constant);

        EvaluationConfig {
            advice,
            instance,
            constant,
            arithmetic_config,
            logical_config,
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
    cond: Option<F>,
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
            cond: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
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
        let c = evaluation_chip.add(
            layouter.namespace(|| "a + b"),
            a.clone(),
            b.clone(),
            self.cond.clone(),
        )?;
        let d = evaluation_chip.sub(
            layouter.namespace(|| "a - b"),
            a.clone(),
            b.clone(),
            self.cond.clone(),
        )?;
        let e = evaluation_chip.mul(
            layouter.namespace(|| "a * b"),
            a.clone(),
            b.clone(),
            self.cond.clone(),
        )?;

        let f = evaluation_chip.eq(layouter.namespace(|| "a == b"), a, b, self.cond.clone())?;

        evaluation_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)?;
        evaluation_chip.expose_public(layouter.namespace(|| "expose d"), d, 1)?;
        evaluation_chip.expose_public(layouter.namespace(|| "expose e"), e, 2)?;
        evaluation_chip.expose_public(layouter.namespace(|| "expose f"), f, 3)?;
        Ok(())
    }
}

#[derive(Clone)]
struct TestBranchCircuit<F: FieldExt> {
    a: Option<F>,
    a_type: MoveValueType,
    b: Option<F>,
    b_type: MoveValueType,
    cond: Option<F>,
}

impl<F: FieldExt> Circuit<F> for TestBranchCircuit<F> {
    type Config = EvaluationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: None,
            a_type: MoveValueType::U8,
            b: None,
            b_type: MoveValueType::U8,
            cond: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
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
        let not_cond = match self.cond {
            Some(v) => Some(F::one() - v),
            None => None,
        };
        let c = evaluation_chip.add(
            layouter.namespace(|| "a + b"),
            a.clone(),
            b.clone(),
            self.cond,
        )?;
        let _d = evaluation_chip.mul(
            layouter.namespace(|| "a * b"),
            a.clone(),
            b.clone(),
            not_cond,
        )?;

        let out = c;
        evaluation_chip.expose_public(layouter.namespace(|| "expose out"), out, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::TestBranchCircuit;
    use crate::circuit::TestCircuit;
    use halo2::dev::MockProver;
    use halo2::pasta::{EqAffine, Fp};
    use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2::poly::commitment::Params;
    use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use movelang::value::MoveValueType;

    #[test]
    fn test_evaluation() {
        // Circuit is very small, we pick a small value here
        let k = 4;

        // Prepare the private and public inputs to the circuit
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = a + b;
        let d = a - b;
        let e = a * b;
        let f = Fp::zero();
        let cond = Fp::one();

        // Instantiate the circuit with the private inputs
        let circuit = TestCircuit {
            a: Some(a),
            a_type: MoveValueType::U8,
            b: Some(b),
            b_type: MoveValueType::U8,
            cond: Some(cond),
        };

        let mut public_inputs = vec![c, d, e, f];

        // Given the correct public input, circuit will verify
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // If use some other public input, the proof will fail
        public_inputs[1] = Fp::one();
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_branch() {
        // Circuit is very small, we pick a small value here
        let k = 4;
        let params: Params<EqAffine> = Params::new(k);

        let empty_circuit = TestBranchCircuit {
            a: None,
            a_type: MoveValueType::U8,
            b: None,
            b_type: MoveValueType::U8,
            cond: None,
        };

        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

        // Prepare the private and public inputs to the circuit
        let a = Fp::from(2);
        let b = Fp::from(3);
        let c = a + b;
        let d = a * b;
        let cond = Fp::one();

        // Instantiate the circuit with the private inputs
        let circuit = TestBranchCircuit {
            a: Some(a),
            a_type: MoveValueType::U8,
            b: Some(b),
            b_type: MoveValueType::U8,
            cond: Some(cond),
        };
        let public_inputs = vec![c];

        // Given the correct public input, circuit will verify
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // If use some other public input, the proof will fail
        let wrong_public_inputs = vec![d];
        let prover = MockProver::run(k, &circuit, vec![wrong_public_inputs]).unwrap();
        assert!(prover.verify().is_err());

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        create_proof(
            &params,
            &pk,
            &[circuit.clone()],
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();

        let msm = params.empty_msm();
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let guard = verify_proof(
            &params,
            pk.get_vk(),
            msm,
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        )
        .unwrap();
        let msm = guard.clone().use_challenges();
        assert!(msm.eval());
    }
}
