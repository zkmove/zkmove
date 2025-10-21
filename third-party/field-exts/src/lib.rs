use halo2_proofs::halo2curves::pasta;
use halo2_proofs::{
    halo2curves::{
        bn256::{Fq, Fr},
        ff::{Field as Halo2Field, FromUniformBytes, PrimeField},
    },
    plonk::Expression,
};

pub use primitive_types::U256;

/// trait to retrieve general operation itentity element
pub trait OpsIdentity {
    /// output type
    type Output;
    /// additive identity
    fn zero() -> Self::Output;
    /// multiplicative identity
    fn one() -> Self::Output;
}

impl<F: Field> OpsIdentity for Expression<F> {
    type Output = Expression<F>;
    fn zero() -> Self::Output {
        Expression::Constant(F::ZERO)
    }

    fn one() -> Self::Output {
        Expression::Constant(F::ONE)
    }
}

// Impl OpsIdentity for Fr
impl OpsIdentity for Fr {
    type Output = Fr;

    fn zero() -> Self::Output {
        Fr::zero()
    }

    fn one() -> Self::Output {
        Fr::one()
    }
}

// Impl OpsIdentity for Fq
impl OpsIdentity for Fq {
    type Output = Fq;

    fn zero() -> Self::Output {
        Fq::zero()
    }

    fn one() -> Self::Output {
        Fq::one()
    }
}

impl OpsIdentity for pasta::Fp {
    type Output = Self;

    fn zero() -> Self::Output {
        Self::ZERO
    }

    fn one() -> Self::Output {
        Self::ONE
    }
}
impl OpsIdentity for pasta::Fq {
    type Output = Self;

    fn zero() -> Self::Output {
        Self::ZERO
    }

    fn one() -> Self::Output {
        Self::ONE
    }
}

/// Trait used to reduce verbosity with the declaration of the [`PrimeField`]
/// trait and its repr.
pub trait Field:
    Halo2Field + PrimeField + FromUniformBytes<64> + Ord + OpsIdentity<Output = Self>
{
    /// Gets the lower 128 bits of this field element when expressed
    /// canonically.
    fn get_lower_128(&self) -> u128 {
        let bytes = self.to_repr();
        bytes.as_ref()[..16]
            .iter()
            .rev()
            .fold(0u128, |acc, value| acc * 256u128 + *value as u128)
    }
    /// Gets the lower 32 bits of this field element when expressed
    /// canonically.
    fn get_lower_32(&self) -> u32 {
        let bytes = self.to_repr();
        bytes.as_ref()[..4]
            .iter()
            .rev()
            .fold(0u32, |acc, value| acc * 256u32 + *value as u32)
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

// Impl custom `Field` trait for BN256 Frq to be used and consistent with the
// rest of the workspace.
impl Field for Fq {}
impl Field for pasta::Fp {}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}
