use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
pub(crate) struct CallContext<F> {
    pub(crate) index: Cell<F>,
    pub(crate) caller_module_index: Cell<F>,
    pub(crate) caller_function_index: Cell<F>,
    pub(crate) caller_pc: Cell<F>,
    pub(crate) version: Cell<F>,
}

impl<F: Field> CallContext<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let index = cb.query_cell();
        let caller_module_index = cb.query_cell();
        let caller_function_index = cb.query_cell();
        let caller_pc = cb.query_cell();
        let version = cb.query_cell();

        Self {
            index,
            caller_module_index,
            caller_function_index,
            caller_pc,
            version,
        }
    }

    pub(crate) fn configure(
        &self,
        cb: &mut ConstraintBuilderV2<F>,
        index: Expression<F>,
        caller_module_index: Expression<F>,
        caller_function_index: Expression<F>,
        caller_pc: Expression<F>,
        version: Expression<F>,
    ) {
        cb.require_equal("call_context.index == index", self.index.expr(), index);
        cb.require_equal(
            "call_context.caller_module_index == caller_module_index",
            self.caller_module_index.expr(),
            caller_module_index,
        );
        cb.require_equal(
            "call_context.caller_function_index == caller_function_index",
            self.caller_function_index.expr(),
            caller_function_index,
        );
        cb.require_equal(
            "call_context.caller_pc == caller_pc",
            self.caller_pc.expr(),
            caller_pc,
        );
        cb.require_equal(
            "call_context.version == version",
            self.version.expr(),
            version,
        );
    }

    pub(crate) fn require_zero(&self, cb: &mut ConstraintBuilderV2<F>) {
        cb.require_zero("index == 0", self.index.expr());
        cb.require_zero("caller_module_index == 0", self.caller_module_index.expr());
        cb.require_zero(
            "caller_function_index == 0",
            self.caller_function_index.expr(),
        );
        cb.require_zero("caller_pc == 0", self.caller_pc.expr());
        cb.require_zero("version == 0", self.version.expr());
    }

    pub(crate) fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.index.expr(),
            self.caller_module_index.expr(),
            self.caller_function_index.expr(),
            self.caller_pc.expr(),
            self.version.expr(),
        ]
    }
}
