// Copyright (c) zkMove Authors

use ff::{Field, FromUniformBytes, PrimeField};

/// Trait used to reduce verbosity with the declaration of the `PrimeField`
pub trait FieldExt: Field + PrimeField<Repr = [u8; 32]> + FromUniformBytes<64> + Ord {
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes[..16]
            .iter()
            .rfold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }
    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes[..4]
            .iter()
            .rfold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

impl FieldExt for pasta_curves::Fp {}
impl FieldExt for pasta_curves::Fq {}
