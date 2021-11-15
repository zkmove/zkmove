use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::Error,
};

pub trait AddInstruction<F: FieldExt>: Chip<F> {
    type Value;

    // `c = a + b`.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error>;
}

pub trait Instructions<F: FieldExt>: AddInstruction<F> {
    type Value;

    fn load_private(
        &self,
        layouter: impl Layouter<F>,
        a: Option<F>,
    ) -> Result<<Self as Instructions<F>>::Value, Error>;

    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<<Self as Instructions<F>>::Value, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        value: <Self as Instructions<F>>::Value,
        row: usize,
    ) -> Result<(), Error>;
}
