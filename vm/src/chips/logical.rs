// Copyright (c) zkMove Authors

use crate::instructions::LogicalInstructions;
use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use movelang::value::MoveValueType;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct LogicalConfig {
    advice: [Column<Advice>; 4],
    s_eq: Selector,
}

pub struct LogicalChip<F: FieldExt> {
    config: LogicalConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for LogicalChip<F> {
    type Config = LogicalConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> LogicalChip<F> {
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
        advice: [Column<Advice>; 4],
    ) -> <Self as Chip<F>>::Config {
        for column in &advice {
            meta.enable_equality((*column).into());
        }
        let s_eq = meta.selector();

        meta.create_gate("eq", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let delta_invert = meta.query_advice(advice[0], Rotation::next());
            let s_eq = meta.query_selector(s_eq) * cond;
            let one = Expression::Constant(F::one());

            vec![
                // if a != b then (a - b) * inverse(a - b) == 1 - out
                // if a == b then (a - b) * 1 == 1 - out
                s_eq * ((lhs - rhs) * delta_invert + (out - one)),
            ]
        });

        LogicalConfig { advice, s_eq }
    }
}

impl<F: FieldExt> LogicalInstructions<F> for LogicalChip<F> {
    type Value = Value<F>;

    fn eq(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
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
                    config.advice[2],
                    0,
                    || value.ok_or(Error::SynthesisError),
                )?;

                region.assign_advice(
                    || "cond",
                    config.advice[3],
                    0,
                    || cond.ok_or(Error::SynthesisError),
                )?;

                region.assign_advice(
                    || "delta invert",
                    config.advice[0],
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
