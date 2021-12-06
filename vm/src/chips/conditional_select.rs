// Copyright (c) zkMove Authors

use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ConditionalSelectConfig {
    advice: [Column<Advice>; 4],
    s_eq: Selector,
}

pub struct ConditionalSelectChip<F: FieldExt> {
    config: ConditionalSelectConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for ConditionalSelectChip<F> {
    type Config = ConditionalSelectConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ConditionalSelectChip<F> {
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

        meta.create_gate("conditional_select", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let cond = meta.query_advice(advice[3], Rotation::cur());
            let s_eq = meta.query_selector(s_eq);

            vec![
                // lhs * cond + rhs * (1 - cond) = out
                s_eq * ((lhs - rhs.clone()) * cond + rhs - out),
            ]
        });

        ConditionalSelectConfig { advice, s_eq }
    }

    pub fn conditional_select(
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<F>,
        b: Value<F>,
        cond: Option<F>,
    ) -> Result<Value<F>, Error> {
        let config = self.config();

        let mut c = None;
        layouter.assign_region(
            || "conditional_select",
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

                let value = match (a.value(), b.value(), cond) {
                    (Some(a), Some(b), Some(cond)) => {
                        let v = if cond == F::one() { a } else { b };
                        Some(v)
                    }
                    _ => None,
                };

                let cell = region.assign_advice(
                    || "select result",
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
