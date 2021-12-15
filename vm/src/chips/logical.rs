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
    s_neq: Selector,
    s_and: Selector,
    s_or: Selector,
    s_not: Selector,
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

        let s_neq = meta.selector();
        meta.create_gate("neq", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let delta_invert = meta.query_advice(advice[0], Rotation::next());
            let s_neq = meta.query_selector(s_neq) * cond;

            vec![
                // if a != b then (a - b) * inverse(a - b) == out
                // if a == b then (a - b) * 1 == out
                s_neq * ((lhs - rhs) * delta_invert - out),
            ]
        });

        let s_and = meta.selector();
        meta.create_gate("and", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_and = meta.query_selector(s_and) * cond;

            vec![s_and * (lhs * rhs - out)]
        });

        let s_or = meta.selector();
        meta.create_gate("or", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_or = meta.query_selector(s_or) * cond;
            let one = Expression::Constant(F::one());

            vec![s_or * ((one.clone() - lhs) * (one.clone() - rhs) - (one - out))]
        });

        let s_not = meta.selector();
        meta.create_gate("not", |meta| {
            let x = meta.query_advice(advice[0], Rotation::cur());
            let out = meta.query_advice(advice[1], Rotation::cur());
            let cond = meta.query_advice(advice[2], Rotation::cur());
            let s_not = meta.query_selector(s_not) * cond;
            let one = Expression::Constant(F::one());

            vec![
                // 1 - x = out
                s_not * (one - x - out)
            ]
        });

        LogicalConfig {
            advice,
            s_eq,
            s_neq,
            s_and,
            s_or,
            s_not,
        }
    }
}

macro_rules! assign_operands {
    ($a:expr, $b:expr, $region:expr, $config:expr) => {{
        let lhs = $region.assign_advice(
            || "lhs",
            $config.advice[0],
            0,
            || $a.value().ok_or(Error::SynthesisError),
        )?;
        let rhs = $region.assign_advice(
            || "rhs",
            $config.advice[1],
            0,
            || $b.value().ok_or(Error::SynthesisError),
        )?;
        $region.constrain_equal($a.cell().unwrap(), lhs)?;
        $region.constrain_equal($b.cell().unwrap(), rhs)?;
    }};
}

macro_rules! assign_cond {
    ($cond:expr, $region:expr, $config:expr) => {{
        $region.assign_advice(
            || "cond",
            $config.advice[3],
            0,
            || $cond.ok_or(Error::SynthesisError),
        )?;
    }};
}

macro_rules! assign_delta_invert {
    ($a:expr, $b:expr, $region:expr, $config:expr) => {{
        $region.assign_advice(
            || "delta invert",
            $config.advice[0],
            1,
            || {
                let delta_invert = if $a.value() == $b.value() {
                    F::one()
                } else {
                    let delta = $a.value().unwrap() - $b.value().unwrap();
                    delta.invert().unwrap()
                };
                Ok(delta_invert)
            },
        )?;
    }};
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

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);
                assign_delta_invert!(a, b, region, config);

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

                c = Some(
                    Value::new_variable(value, Some(cell), MoveValueType::Bool)
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }

    fn neq(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "neq",
            |mut region: Region<'_, F>| {
                config.s_neq.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);
                assign_delta_invert!(a, b, region, config);

                let value = match (a.value(), b.value()) {
                    (Some(a), Some(b)) => {
                        let v = if a != b { F::one() } else { F::zero() };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "lhs != rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::SynthesisError),
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

    fn and(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "and",
            |mut region: Region<'_, F>| {
                config.s_and.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let value = match (a.value(), b.value()) {
                    (Some(a), Some(b)) => {
                        let v = if a == F::zero() || b == F::zero() {
                            F::zero()
                        } else {
                            F::one()
                        };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "lhs && rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::SynthesisError),
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

    fn or(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "or",
            |mut region: Region<'_, F>| {
                config.s_or.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let value = match (a.value(), b.value()) {
                    (Some(a), Some(b)) => {
                        let v = if a == F::zero() && b == F::zero() {
                            F::zero()
                        } else {
                            F::one()
                        };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "lhs || rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::SynthesisError),
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

    fn not(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut b = None;
        layouter.assign_region(
            || "not",
            |mut region: Region<'_, F>| {
                config.s_not.enable(&mut region, 0)?;

                // assign operand
                let x = region.assign_advice(
                    || "x",
                config.advice[0],
                0,
                || a.value().ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(a.cell().unwrap(), x)?;

                // assign cond
                region.assign_advice(
                    || "cond",
                config.advice[2],
                0,
                || cond.ok_or(Error::SynthesisError),
                )?;

                let value = match a.value() {
                    Some(a) => {
                        let v = if a == F::zero() {
                            F::one()
                        } else {
                            F::zero()
                        };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "not a",
                    config.advice[1],
                    0,
                    || value.ok_or(Error::SynthesisError),
                )?;

                b = Some(
                    Value::new_variable(value, Some(cell), MoveValueType::Bool)
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;

        Ok(b.unwrap())
    }
}
