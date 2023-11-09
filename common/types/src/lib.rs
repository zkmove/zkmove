use halo2_proofs::halo2curves::{
    bn256::{Fq, Fr},
    ff::{Field as Halo2Field, FromUniformBytes, PrimeField},
    pasta::Fp,
};

pub trait Field: Halo2Field + PrimeField<Repr = [u8; 32]> + FromUniformBytes<64> + Ord {
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes[..16]
            .iter()
            .rev()
            .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }

    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes[..4]
            .iter()
            .rev()
            .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

impl Field for Fr {}

impl Field for Fq {}

impl Field for Fp {}
