// Copyright (c) zkMove Authors

use anyhow::Result;
use fields::FieldExt;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, Mds, Spec};
use std::marker::PhantomData;

/// The same Poseidon specification as poseidon::P128Pow5T3
#[derive(Debug, Clone)]
pub struct SmtP128Pow5T3<F: FieldExt, const SECURE_MDS: usize>(PhantomData<F>);

impl<F: FieldExt, const SECURE_MDS: usize> SmtP128Pow5T3<F, SECURE_MDS> {
    pub fn new() -> Self {
        SmtP128Pow5T3(PhantomData::default())
    }
}

impl<F: FieldExt, const SECURE_MDS: usize> Spec<F, 3, 2> for SmtP128Pow5T3<F, SECURE_MDS> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: F) -> F {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        SECURE_MDS
    }

    fn constants() -> (Vec<[F; 3]>, Mds<F, 3>, Mds<F, 3>) {
        // FIXME
        todo!()
    }
}

impl<F: FieldExt, const SECURE_MDS: usize> Default for SmtP128Pow5T3<F, SECURE_MDS> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Poseidon<F: FieldExt, const L: usize>(PhantomData<F>);

impl<F: FieldExt, const L: usize> Poseidon<F, L> {
    pub fn new() -> Self {
        Poseidon(PhantomData::default())
    }
}

pub trait FieldHasher<F: FieldExt, const L: usize> {
    fn hash(&self, inputs: [F; L]) -> Result<F>;
    fn hasher() -> Self;
}

impl<F, const L: usize> FieldHasher<F, L> for Poseidon<F, L>
where
    F: FieldExt,
{
    fn hash(&self, inputs: [F; L]) -> Result<F> {
        Ok(Hash::<_, SmtP128Pow5T3<F, 0>, ConstantLength<L>, 3, 2>::init().hash(inputs))
    }

    fn hasher() -> Self {
        Poseidon::<F, L>::default()
    }
}

impl<F: FieldExt, const L: usize> Default for Poseidon<F, L> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // todo. for permute is private function within PSE Halo2.
    // this function should be changed correspondly.
    // use crate::poseidon::{FieldHasher, Poseidon, SmtP128Pow5T3};
    // use halo2_gadgets::poseidon::primitives::{permute, Spec};
    // use halo2_gadgets::poseidon::primitives::Spec;
    // use fields::FieldExt;
    // use halo2_proofs::halo2curves::pasta::Fp;

    #[test]
    fn orchard_spec_equivalence() {
        // let message = [Fp::from(6), Fp::from(42)];
        // let (round_constants, mds, _) = SmtP128Pow5T3::<Fp, 0>::constants();

        // let poseidon = Poseidon::<Fp, 2>::new();
        // let result = poseidon.hash(message).unwrap();

        // // The result should be equivalent to just directly applying the permutation and
        // // taking the first state element as the output.
        // let mut state = [message[0], message[1], Fp::from_u128(2 << 64)];
        // permute::<_, SmtP128Pow5T3<Fp, 0>, 3, 2>(&mut state, &mds, &round_constants);
        // assert_eq!(state[0], result);
    }
}
