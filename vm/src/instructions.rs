use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::Error,
};
use movelang::value::MoveValueType;

pub trait ArithmeticInstructions<F: FieldExt>: Chip<F> {
    type Value;

    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error>;
}

pub trait LogicalInstructions<F: FieldExt>: Chip<F> {
    type Value;

    fn eq(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error>;
}

pub trait Instructions<F: FieldExt>: ArithmeticInstructions<F> {
    type Value;

    fn load_private(
        &self,
        layouter: impl Layouter<F>,
        a: Option<F>,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error>;

    fn load_constant(
        &self,
        layouter: impl Layouter<F>,
        constant: F,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        value: <Self as Instructions<F>>::Value,
        row: usize,
    ) -> Result<(), Error>;
}
