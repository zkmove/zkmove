use bellman::pairing::Engine;
use bellman::Variable;

pub struct Value<E: Engine> {
    pub value: Option<E::Fr>,
    pub variable: Variable,
}
