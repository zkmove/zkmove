use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{
    FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, OPCODE, PC, SP,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use gadgets::util::not;
use types::Field;

#[derive(Clone, Debug)]
pub struct Ret<F> {
    is_zero_frame_index: IsZeroGadget<F>,
}

impl<F: Field> InstructionGadgetV2<F> for Ret<F> {
    const NAME: &'static str = "Ret";
    const OPCODE: Opcode = Opcode::Ret;
    const EXECUTION_STATE: ExecutionState = ExecutionState::Ret;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let is_zero_frame_index = IsZeroGadget::construct(cb, step_curr.frame_index.expr());

        cb.require_equal(
            "opcode",
            step_curr.opcode.expr(),
            (Self::OPCODE as u64).expr(),
        );
        cb.require_equal(
            format!("{}, step_counter(0) == 1", Self::NAME),
            step_curr.step_counter.expr(),
            1u64.expr(),
        );

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.condition(is_zero_frame_index.expr(), |cb| {
            cb.require_next_state(ExecutionState::Stop);
            //TODO: state transition, go to NOP when necessary
        });
        cb.condition(not::expr(is_zero_frame_index.expr()), |cb| {
            cb.require_state_transition(vec![
                (
                    MODULE_INDEX,
                    Transition::To(step_curr.caller_module_index.expr()),
                ),
                (
                    FUNCTION_INDEX,
                    Transition::To(step_curr.caller_function_index.expr()),
                ),
                (PC, Transition::To(step_curr.caller_pc.expr() + 1u64.expr())),
                (FRAME_INDEX, Transition::Delta((-1).expr())),
                (SP, Transition::Same),
            ]);
        });

        Ret {
            is_zero_frame_index,
        }
    }
}
