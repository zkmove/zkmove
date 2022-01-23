// Copyright (c) zkMove Authors

use crate::chips::arithmetic::{ArithmeticChip, ArithmeticConfig};
use crate::chips::conditional_select::{ConditionalSelectChip, ConditionalSelectConfig};
use crate::chips::logical::{LogicalChip, LogicalConfig};
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
use crate::value::Value;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance},
};
use movelang::value::MoveValueType;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct EvaluationConfig {
    advice: [Column<Advice>; 4],

    // Public inputs
    instance: Column<Instance>,

    // Fixed column to load constants
    constant: Column<Fixed>,

    arithmetic_config: ArithmeticConfig,
    logical_config: LogicalConfig,
    conditional_select_config: ConditionalSelectConfig,
}

pub struct EvaluationChip<F: FieldExt> {
    config: EvaluationConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithmeticInstructions<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.add(layouter, a, b, cond)
    }

    fn sub(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.sub(layouter, a, b, cond)
    }

    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.mul(layouter, a, b, cond)
    }

    fn div(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.div(layouter, a, b, cond)
    }

    fn rem(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().arithmetic_config.clone();

        let arithmetic_chip = ArithmeticChip::<F>::construct(config, ());
        arithmetic_chip.rem(layouter, a, b, cond)
    }
}

impl<F: FieldExt> LogicalInstructions<F> for EvaluationChip<F> {
    type Value = Value<F>;
    fn eq(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.eq(layouter, a, b, cond)
    }

    fn neq(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.neq(layouter, a, b, cond)
    }

    fn and(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.and(layouter, a, b, cond)
    }

    fn or(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.or(layouter, a, b, cond)
    }

    fn not(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        cond: Option<F>,
    ) -> Result<Self::Value, Error> {
        let config = self.config().logical_config.clone();

        let logical_chip = LogicalChip::<F>::construct(config, ());
        logical_chip.not(layouter, a, cond)
    }
}

impl<F: FieldExt> Chip<F> for EvaluationChip<F> {
    type Config = EvaluationConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> EvaluationChip<F> {
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
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        let arithmetic_config = ArithmeticChip::configure(meta, advice);
        let logical_config = LogicalChip::configure(meta, advice);
        let conditional_select_config = ConditionalSelectChip::configure(meta, advice);

        meta.enable_equality(instance.into());
        meta.enable_constant(constant);

        EvaluationConfig {
            advice,
            instance,
            constant,
            arithmetic_config,
            logical_config,
            conditional_select_config,
            //other config
        }
    }

    pub fn conditional_select(
        &self,
        layouter: impl Layouter<F>,
        a: Value<F>,
        b: Value<F>,
        cond: Option<F>,
    ) -> Result<Value<F>, Error> {
        let config = self.config().conditional_select_config.clone();

        let conditional_select_chip = ConditionalSelectChip::<F>::construct(config, ());
        conditional_select_chip.conditional_select(layouter, a, b, cond)
    }
}

impl<F: FieldExt> Instructions<F> for EvaluationChip<F> {
    type Value = Value<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error> {
        let config = self.config();

        let mut alloc = None;
        layouter.assign_region(
            || "load private",
            |mut region| {
                let cell = region.assign_advice(
                    || "private input",
                    config.advice[0],
                    0,
                    || value.ok_or(Error::SynthesisError),
                )?;
                alloc = Some(
                    Value::new_variable(value, Some(cell), ty.clone())
                        .map_err(|_| Error::SynthesisError)?,
                );
                Ok(())
            },
        )?;
        Ok(alloc.unwrap())
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
        ty: MoveValueType,
    ) -> Result<<Self as Instructions<F>>::Value, Error> {
        let config = self.config();

        let mut alloc = None;
        layouter.assign_region(
            || "load constant",
            |mut region| {
                let cell = region.assign_fixed(
                    || "constant value",
                    config.constant,
                    0,
                    || Ok(constant),
                )?;
                alloc = Some(
                    Value::new_constant(constant, Some(cell), ty.clone())
                        .map_err(|_| Error::SynthesisError)?,
                );

                Ok(())
            },
        )?;
        Ok(alloc.unwrap())
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        value: <Self as Instructions<F>>::Value,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(value.cell().unwrap(), config.instance, row)
    }
}
