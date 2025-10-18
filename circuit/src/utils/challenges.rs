use crate::utils::query_expression;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Challenge, ConstraintSystem, Expression, FirstPhase, SecondPhase};
use types::Field;

/// All challenges used in circuits.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    row_keccak_input: T,
    column_keccak_input: T,
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        // // Dummy columns are required in the test circuits
        // // In some tests there might be no advice columns before the phase, so Halo2 will panic with
        // // "No Column<Advice> is used in phase Phase(1) while allocating a new 'Challenge usable
        // // after phase Phase(1)'"
        // #[cfg(any(test, feature = "test-circuits"))]
        // let _dummy_cols = [meta.advice_column(), meta.advice_column_in(SecondPhase)];

        Self {
            row_keccak_input: meta.challenge_usable_after(FirstPhase),
            column_keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [keccak_input, column_keccak_input, lookup_input] = query_expression(meta, |meta| {
            [
                self.row_keccak_input,
                self.column_keccak_input,
                self.lookup_input,
            ]
            .map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            row_keccak_input: keccak_input,
            column_keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            row_keccak_input: layouter.get_challenge(self.row_keccak_input),
            column_keccak_input: layouter.get_challenge(self.column_keccak_input),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `keccak_input`.
    pub fn row_keccak_input(&self) -> T {
        self.row_keccak_input.clone()
    }

    /// Returns challenge of `column_keccak_input`.
    pub fn column_keccak_input(&self) -> T {
        self.column_keccak_input.clone()
    }

    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [
            &self.row_keccak_input,
            &self.column_keccak_input,
            &self.lookup_input,
        ]
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_row_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.row_keccak_input.clone())
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_column_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.column_keccak_input.clone())
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}
