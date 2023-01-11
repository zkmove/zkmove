// Copyright (c) zkMove Authors

use anyhow::{anyhow, Result};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, Spec};
use halo2_proofs::arithmetic::FieldExt;
use std::convert::TryInto;
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

/// An adapter to handle variable input length. Maximum input length is 16.
pub struct PoseidonAdapter<F: FieldExt>(PhantomData<F>);

impl<F: FieldExt> PoseidonAdapter<F> {
    pub fn hash(inputs: Vec<F>) -> Result<F> {
        match inputs.len() {
            1 => Poseidon::<F, 1>::new().hash(inputs.try_into().unwrap()),
            2 => Poseidon::<F, 2>::new().hash(inputs.try_into().unwrap()),
            3 => Poseidon::<F, 3>::new().hash(inputs.try_into().unwrap()),
            4 => Poseidon::<F, 4>::new().hash(inputs.try_into().unwrap()),
            5 => Poseidon::<F, 5>::new().hash(inputs.try_into().unwrap()),
            6 => Poseidon::<F, 6>::new().hash(inputs.try_into().unwrap()),
            7 => Poseidon::<F, 7>::new().hash(inputs.try_into().unwrap()),
            8 => Poseidon::<F, 8>::new().hash(inputs.try_into().unwrap()),
            9 => Poseidon::<F, 9>::new().hash(inputs.try_into().unwrap()),
            10 => Poseidon::<F, 10>::new().hash(inputs.try_into().unwrap()),
            11 => Poseidon::<F, 11>::new().hash(inputs.try_into().unwrap()),
            12 => Poseidon::<F, 12>::new().hash(inputs.try_into().unwrap()),
            13 => Poseidon::<F, 13>::new().hash(inputs.try_into().unwrap()),
            14 => Poseidon::<F, 14>::new().hash(inputs.try_into().unwrap()),
            15 => Poseidon::<F, 15>::new().hash(inputs.try_into().unwrap()),
            16 => Poseidon::<F, 16>::new().hash(inputs.try_into().unwrap()),
            _ => Err(anyhow!("input length out of range")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::poseidon::{FieldHasher, Poseidon, SmtP128Pow5T3};
    use halo2_gadgets::poseidon::primitives::{permute, Spec};
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::pasta::Fp;

    #[test]
    fn orchard_spec_equivalence() {
        let message = [Fp::from(6), Fp::from(42)];
        let (round_constants, mds, _) = SmtP128Pow5T3::<Fp, 0>::constants();

        let poseidon = Poseidon::<Fp, 2>::new();
        let result = poseidon.hash(message).unwrap();

        // The result should be equivalent to just directly applying the permutation and
        // taking the first state element as the output.
        let mut state = [message[0], message[1], Fp::from_u128(2 << 64)];
        permute::<_, SmtP128Pow5T3<Fp, 0>, 3, 2>(&mut state, &mds, &round_constants);
        assert_eq!(state[0], result);
    }
}
