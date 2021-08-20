use bellman::pairing::Engine;
use bellman::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use logger::prelude::*;

pub struct DummyCS<E: Engine> {
    inputs: Vec<E::Fr>,
    witness: Vec<E::Fr>,
}

impl<E> DummyCS<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        Self {
            inputs: vec![],
            witness: vec![],
        }
    }
}

impl<E: Engine> ConstraintSystem<E> for DummyCS<E> {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let name = annotation().into();
        let value = f()?;
        self.witness.push(value);
        let index = self.witness.len() - 1;
        let variable = Variable::new_unchecked(Index::Aux(index));
        debug!(
            "DummyCS alloc {}, value = {}, index = {}",
            name, value, index
        );
        Ok(variable)
    }

    fn alloc_input<F, A, AR>(&mut self, annotation: A, f: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let name = annotation().into();
        let value = f()?;
        self.inputs.push(value);
        let index = self.inputs.len() - 1;
        let variable = Variable::new_unchecked(Index::Aux(index));
        debug!(
            "DummyCS alloc_input {}, value = {}, index = {}",
            name, value, index
        );
        Ok(variable)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
        LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
    {
        let _a = a(LinearCombination::zero());
        let _b = b(LinearCombination::zero());
        let _c = c(LinearCombination::zero());
        debug!("DummyCS enforce: {}", annotation().into());
    }

    fn push_namespace<NR, N>(&mut self, _name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}
