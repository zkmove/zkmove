// Copyright (c) zkMove Authors

use crate::instructions::ArithmeticInstructions;
use crate::value::Value;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use logger::prelude::*;
use movelang::value::{convert_to_field, move_div, move_rem, MoveValue};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ArithmeticConfig {
    advice: [Column<Advice>; 4],
    s_add: Selector,
    s_sub: Selector,
    s_mul: Selector,
    s_div_rem: Selector,
}

pub struct ArithmeticChip<F: FieldExt> {
    config: ArithmeticConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for ArithmeticChip<F> {
    type Config = ArithmeticConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ArithmeticChip<F> {
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
            meta.enable_equality((*column));
        }

        let s_add = meta.selector();
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_add = meta.query_selector(s_add) * cond;

            vec![s_add * (lhs + rhs - out)]
        });

        let s_sub = meta.selector();
        meta.create_gate("sub", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_sub = meta.query_selector(s_sub) * cond;

            vec![s_sub * (lhs - rhs - out)]
        });

        let s_mul = meta.selector();
        meta.create_gate("mul", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_mul = meta.query_selector(s_mul) * cond;

            vec![s_mul * (lhs * rhs - out)]
        });

        let s_div_rem = meta.selector();
        meta.create_gate("div_rem", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let quotient = meta.query_advice(advice[2], Rotation::cur());
            let remainder = meta.query_advice(advice[0], Rotation::next());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_div_rem = meta.query_selector(s_div_rem) * cond;

            vec![s_div_rem * (lhs - rhs * quotient - remainder)]
        });

        ArithmeticConfig {
            advice,
            s_add,
            s_sub,
            s_mul,
            s_div_rem,
        }
    }
}

macro_rules! assign_operands {
    ($a:expr, $b:expr, $region:expr, $config:expr) => {{
        let lhs = $region.assign_advice(
            || "lhs",
            $config.advice[0],
            0,
            || $a.value().ok_or(Error::Synthesis),
        )?;
        let rhs = $region.assign_advice(
            || "rhs",
            $config.advice[1],
            0,
            || $b.value().ok_or(Error::Synthesis),
        )?;
        $region.constrain_equal($a.cell().unwrap(), lhs.cell())?;
        $region.constrain_equal($b.cell().unwrap(), rhs.cell())?;
    }};
}

macro_rules! assign_cond {
    ($cond:expr, $region:expr, $config:expr) => {{
        $region.assign_advice(
            || "cond",
            $config.advice[3],
            0,
            || $cond.ok_or(Error::Synthesis),
        )?;
    }};
}

macro_rules! div_rem {
    ($a:expr, $b:expr) => {{
        let l_move: Option<MoveValue> = $a.clone().into();
        let r_move: Option<MoveValue> = $b.clone().into();
        match (l_move, r_move) {
            (Some(l), Some(r)) => {
                let quo = move_div(l.clone(), r.clone()).map_err(|e| {
                    error!("move div failed: {:?}", e);
                    Error::Synthesis
                })?;
                let rem = move_rem(l, r).map_err(|e| {
                    error!("move rem failed: {:?}", e);
                    Error::Synthesis
                })?;
                (
                    Some(convert_to_field::<F>(quo)),
                    Some(convert_to_field::<F>(rem)),
                )
            }
            _ => (None, None),
        }
    }};
}

impl<F: FieldExt> ArithmeticInstructions<F> for ArithmeticChip<F> {
    type Value = Value<F>;

    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                config.s_add.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let value = a.value().and_then(|a| b.value().map(|b| a + b));
                let cell = region.assign_advice(
                    || "lhs + rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::Synthesis),
                )?;
                c = Some(
                    Value::new_variable(value, Some(cell.cell()), a.ty())
                        .map_err(|_| Error::Synthesis)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }

    fn sub(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "sub",
            |mut region: Region<'_, F>| {
                config.s_sub.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let value = a.value().and_then(|a| b.value().map(|b| a - b));
                let cell = region.assign_advice(
                    || "lhs - rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::Synthesis),
                )?;
                c = Some(
                    Value::new_variable(value, Some(cell.cell()), a.ty())
                        .map_err(|_| Error::Synthesis)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                config.s_mul.enable(&mut region, 0)?;

                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let value = a.value().and_then(|a| b.value().map(|b| a * b));
                let cell = region.assign_advice(
                    || "lhs * rhs",
                    config.advice[2],
                    0,
                    || value.ok_or(Error::Synthesis),
                )?;
                c = Some(
                    Value::new_variable(value, Some(cell.cell()), a.ty())
                        .map_err(|_| Error::Synthesis)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }

    fn div(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "div",
            |mut region: Region<'_, F>| {
                config.s_div_rem.enable(&mut region, 0)?;

                let (quotient, remainder) = div_rem!(a, b);
                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let quotient_cell = region.assign_advice(
                    || "quotient",
                    config.advice[2],
                    0,
                    || quotient.ok_or(Error::Synthesis),
                )?;

                let _remainder_cell = region.assign_advice(
                    || "remainder",
                    config.advice[0],
                    1,
                    || remainder.ok_or(Error::Synthesis),
                )?;
                c = Some(
                    Value::new_variable(quotient, Some(quotient_cell.cell()), a.ty())
                        .map_err(|_| Error::Synthesis)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }

    fn rem(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "rem",
            |mut region: Region<'_, F>| {
                config.s_div_rem.enable(&mut region, 0)?;

                let (quotient, remainder) = div_rem!(a, b);
                assign_operands!(a, b, region, config);
                assign_cond!(cond, region, config);

                let _quotient_cell = region.assign_advice(
                    || "quotient",
                    config.advice[2],
                    0,
                    || quotient.ok_or(Error::Synthesis),
                )?;

                let remainder_cell = region.assign_advice(
                    || "remainder",
                    config.advice[0],
                    1,
                    || remainder.ok_or(Error::Synthesis),
                )?;
                c = Some(
                    Value::new_variable(remainder, Some(remainder_cell.cell()), a.ty())
                        .map_err(|_| Error::Synthesis)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }
}
