use crate::instructions::ArithmeticInstructions;
use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ArithmeticConfig {
    advice: [Column<Advice>; 4],
    s_add: Selector,
    s_sub: Selector,
    s_mul: Selector,
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
            meta.enable_equality((*column).into());
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
        meta.create_gate("sub", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_mul = meta.query_selector(s_mul) * cond;

            vec![s_mul * (lhs * rhs - out)]
        });

        ArithmeticConfig {
            advice,
            s_add,
            s_sub,
            s_mul,
        }
    }
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

                let value = a.value().and_then(|a| b.value().map(|b| a + b));
                let cell = region.assign_advice(
                    || "lhs + rhs",
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

                c = Some(
                    Value::new_variable(value, Some(cell), a.ty())
                        .map_err(|_| Error::SynthesisError)?,
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

                let value = a.value().and_then(|a| b.value().map(|b| a - b));
                let cell = region.assign_advice(
                    || "lhs - rhs",
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

                c = Some(
                    Value::new_variable(value, Some(cell), a.ty())
                        .map_err(|_| Error::SynthesisError)?,
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

                let value = a.value().and_then(|a| b.value().map(|b| a * b));
                let cell = region.assign_advice(
                    || "lhs * rhs",
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

                c = Some(
                    Value::new_variable(value, Some(cell), a.ty())
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;

        Ok(c.unwrap())
    }
}
