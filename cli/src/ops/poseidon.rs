// Copyright (c) zkMove Authors

//! Poseidon hashing utility, decoupled from CLI argument parsing.

use anyhow::Result;
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use move_core_types::u256::U256;

/// Domain spec for the Poseidon hash.
pub const DOMAIN_SPEC: u64 = 1;

/// Compute `poseidon_hash(value, nonce)` returning the result as a `U256`.
pub fn poseidon_hash(value: u128, nonce: u128) -> Result<U256> {
    let hash_result = poseidon_base::Hashable::hash_with_domain(
        [Fr::from_u128(value), Fr::from_u128(nonce)],
        Fr::from(DOMAIN_SPEC),
    );
    let hash_val = U256::from_le_bytes(&hash_result.to_repr().as_ref().try_into()?);
    Ok(hash_val)
}
