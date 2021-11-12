use crate::instructions::{AddInstruction, Instructions};
use crate::plonk::add::{AddChip, AddConfig};
use crate::value::Alloc;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
struct FieldConfig {
    advice: [Column<Advice>; 2],

    // Public inputs
    instance: Column<Instance>,

    add_config: AddConfig,
}

struct InstructionsChip<F: FieldExt> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AddInstruction<F> for InstructionsChip<F> {
    type Value = Alloc<F>;
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Value,
        b: Self::Value,
    ) -> Result<Self::Value, Error> {
        let config = self.config().add_config.clone();

        let add_chip = AddChip::<F>::construct(config, ());
        add_chip.add(layouter, a, b)
    }
}

impl<F: FieldExt> Chip<F> for InstructionsChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> InstructionsChip<F> {
    fn construct(config: <Self as Chip<F>>::Config, _loaded: <Self as Chip<F>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        let add_config = AddChip::configure(meta, advice);

        meta.enable_equality(instance.into());

        FieldConfig {
            advice,
            instance,
            add_config,
            //other config
        }
    }
}

impl<F: FieldExt> Instructions<F> for InstructionsChip<F> {
    type Value = Alloc<F>;

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Option<F>,
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
                alloc = Some(Alloc { cell, value });
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

        layouter.constrain_instance(value.cell, config.instance, row)
    }
}

#[derive(Default)]
struct TestCircuit<F: FieldExt> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();

        InstructionsChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let instructions_chip = InstructionsChip::<F>::construct(config, ());

        let a = instructions_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = instructions_chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = instructions_chip.add(layouter.namespace(|| "a + b"), a, b)?;

        instructions_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }
}
