use crate::chips::utilities::Expr;
use halo2_proofs::plonk::Expression;
use types::Field;

pub(crate) struct CallContext<F> {
    pub(crate) index: Expression<F>,
    pub(crate) caller_module_index: Expression<F>,
    pub(crate) caller_function_index: Expression<F>,
    pub(crate) caller_pc: Expression<F>,
    pub(crate) version: Expression<F>,
}
impl<F: Field> Default for CallContext<F> {
    fn default() -> Self {
        Self {
            index: 0u64.expr(),
            caller_module_index: 0u64.expr(),
            caller_function_index: 0u64.expr(),
            caller_pc: 0u64.expr(),
            version: 0u64.expr(),
        }
    }
}

#[derive(Default)]
pub(crate) struct CallStackPush<F: Field>(pub CallContext<F>);
#[derive(Default)]
pub(crate) struct CallStackPop<F: Field>(pub CallContext<F>);

pub(crate) enum Shuffle<F: Field> {
    CallStack(CallStackPush<F>, CallStackPop<F>),
    /// Conditional shuffle enabled by the first element.
    Conditional(Expression<F>, Box<Shuffle<F>>),
}

impl<F: Field> Shuffle<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::CallStack(input, _) => {
                vec![
                    input.0.index.clone(),
                    input.0.caller_module_index.clone(),
                    input.0.caller_function_index.clone(),
                    input.0.caller_pc.clone(),
                    input.0.version.clone(),
                ]
            }
            Self::Conditional(condition, shuffle) => shuffle
                .input_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }

    pub(crate) fn shuffled_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::CallStack(_, shuffled) => {
                vec![
                    shuffled.0.index.clone(),
                    shuffled.0.caller_module_index.clone(),
                    shuffled.0.caller_function_index.clone(),
                    shuffled.0.caller_pc.clone(),
                    shuffled.0.version.clone(),
                ]
            }
            Self::Conditional(condition, shuffle) => shuffle
                .shuffled_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }
}
