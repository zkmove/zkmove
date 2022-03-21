use crate::evaluation_chip::{EvaluationChip, EvaluationConfig};
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use movelang::value::MoveValueType;

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
            self.cond,
        )?;
        let d = evaluation_chip.sub(
            layouter.namespace(|| "a - b"),
            a.clone(),
            b.clone(),
            self.cond,
        )?;
        let e = evaluation_chip.mul(
            layouter.namespace(|| "a * b"),
            a.clone(),
            b.clone(),
            self.cond,
        )?;

        let f = evaluation_chip.eq(layouter.namespace(|| "a == b"), a, b, self.cond)?;

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
        let d = evaluation_chip.mul(layouter.namespace(|| "a * b"), a, b, not_cond)?;

        let out = evaluation_chip.conditional_select(
            layouter.namespace(|| "conditional select"),
            c,
            d,
            self.cond,
        )?;
        evaluation_chip.expose_public(layouter.namespace(|| "expose out"), out, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::chip_tests::TestBranchCircuit;
    use crate::chip_tests::TestCircuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::{EqAffine, Fp};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use movelang::value::MoveValueType;
    use rand_core::OsRng;

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
            &[circuit],
            &[&[public_inputs.as_slice()]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);

        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        );
        assert!(result.is_ok());
    }
}
