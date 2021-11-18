use crate::instructions::EqInstruction;
use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;
use movelang::value::MoveValueType;

#[derive(Clone, Debug)]
pub struct EqConfig {
    advice: [Column<Advice>; 2],
    s_eq: Selector,
}

pub struct EqChip<F: FieldExt> {
    config: EqConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for EqChip<F> {
    type Config = EqConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> EqChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
    ) -> <Self as Chip<F>>::Config {
        for column in &advice {
            meta.enable_equality((*column).into());
        }
        let s_eq = meta.selector();

        meta.create_gate("eq", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let delta_invert = meta.query_advice(advice[1], Rotation::next());
            let s_eq = meta.query_selector(s_eq);
            let one = Expression::Constant(F::one());

            vec![
                // if a != b then (a - b) * inverse(a - b) == 1 - out
                // if a == b then (a - b) * 1 == 1 - out
                s_eq * ((lhs - rhs) * delta_invert + (out - one))
            ]

        });

        EqConfig { advice, s_eq }
    }
}

impl<F: FieldExt> EqInstruction<F> for EqChip<F> {
    type Value = Value<F>;

    fn eq(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "eq",
            |mut region: Region<'_, F>| {
                config.s_eq.enable(&mut region, 0)?;

                let lhs = region.assign_advice(
                    || "lhs",
                    config.advice[0],
                    0,
                    || a.value().ok_or(Error::SynthesisError),
                )?;
                let rhs = region.assign_advice(
                    || "rhs",
                    config.advice[1],
                    0,
                    || b.value().ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(a.cell().unwrap(), lhs)?;
                region.constrain_equal(b.cell().unwrap(), rhs)?;

                let value = match (a.value(), b.value()) {
                    (Some(a), Some(b)) => {
                        let v = if a == b { F::one() } else { F::zero() };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "lhs == rhs",
                    config.advice[0],
                    1,
                    || value.ok_or(Error::SynthesisError),
                )?;

                region.assign_advice(
                    || "delta invert",
                    config.advice[1],
                    1,
                    || {
                        let delta_invert = if a.value() == b.value() {
                            F::one()
                        } else {
                            let delta = a.value().unwrap() - b.value().unwrap();
                            delta.invert().unwrap()
                        };
                        Ok(delta_invert)
                    },
                )?;

                c = Some(
                    Value::new_variable(value, Some(cell), MoveValueType::Bool)
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }
}
