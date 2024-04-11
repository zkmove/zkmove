use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct BrBool<F, const TRUE: bool> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const TRUE: bool> InstructionGadgetV2<F> for BrBool<F, TRUE> {
    const NAME: &'static str = match TRUE {
        true => "BRTRUE",
        false => "BRFALSE",
    };

    const OPCODE: Opcode = match TRUE {
        true => Opcode::BrTrue,
        false => Opcode::BrFalse,
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        // TODO: abstract state transition.
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, step_counter(0) == 1", Self::NAME),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
            // TODO: add bytecode lookup
        });
        cb.last_row(|cb| {
            cb.require_zero(
                format!(
                    "{}, last_row: module_index(1) == module_index(0)",
                    Self::NAME
                ),
                cb.next.state.module_index.expr() - cb.curr.state.module_index.expr(),
            );
            cb.require_zero(
                format!(
                    "{}, last_row: function_index(1) == function_index(0)",
                    Self::NAME
                ),
                cb.next.state.function_index.expr() - cb.curr.state.function_index.expr(),
            );
            cb.require_zero(
                format!(
                    "{}, last_row: module_index(1) == module_index(0)",
                    Self::NAME
                ),
                cb.next.state.frame_index.expr() - cb.curr.state.frame_index.expr(),
            );
            cb.require_zero(
                format!("{}, last_row: frame_index(1) == frame_index(0)", Self::NAME),
                cb.next.state.frame_index.expr() - cb.curr.state.frame_index.expr(),
            );
            cb.require_equal(
                format!("{}, last_row: sp(1) == sp(0) - 1", Self::NAME),
                cb.next.state.sp.expr(),
                cb.curr.state.sp.expr() - 1u64.expr(),
            );
        });
        BrBool {
            phantom_data: PhantomData,
        }
    }
}
