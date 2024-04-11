use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
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
        cb.first_row(|cb| {
            cb.require_zero(
                format!("{}, step_counter(0) == 1", Self::NAME),
                cb.curr.state.step_counter.expr() - 1u64.expr(),
            );
            // TODO: add bytecode lookup
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (PC, Transition::Delta(1u64.expr())),
                (SP, Transition::Delta(-1.expr())),
            ]);
        });

        BrBool {
            phantom_data: PhantomData,
        }
    }
}
