use halo2_proofs::plonk::Expression;

use field_exts::Field;

#[derive(Clone, Debug)]
pub(crate) struct CallContext<T> {
    pub(crate) index: T,
    pub(crate) caller_module_index: T,
    pub(crate) caller_function_index: T,
    pub(crate) caller_pc: T,
    pub(crate) version: T,
}

impl<F: Field> CallContext<Expression<F>> {
    pub(crate) fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.index.clone(),
            self.caller_module_index.clone(),
            self.caller_function_index.clone(),
            self.caller_pc.clone(),
            self.version.clone(),
        ]
    }
}
