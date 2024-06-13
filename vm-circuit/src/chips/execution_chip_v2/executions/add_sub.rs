use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::add::AddGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use types::Field;

#[derive(Clone, Debug)]
pub struct Add<F, const N_BYTES: usize, const ADD: bool> {
    add_gadget: Option<AddGadget<F, N_BYTES, ADD>>,
}
impl<F: Field, const N_BYTES: usize, const ADD: bool> InstructionGadgetV2<F>
    for Add<F, N_BYTES, ADD>
{
    const NAME: &'static str = if ADD { "Add" } else { "Sub" };
    const OPCODE: Opcode = if ADD { Opcode::Add } else { Opcode::Sub };
    const EXECUTION_STATE: ExecutionState = if ADD {
        match N_BYTES {
            NUM_OF_BYTES_U8 => ExecutionState::AddU8,
            NUM_OF_BYTES_U16 => ExecutionState::AddU16,
            NUM_OF_BYTES_U32 => ExecutionState::AddU32,
            NUM_OF_BYTES_U64 => ExecutionState::AddU64,
            NUM_OF_BYTES_U128 => ExecutionState::AddU128,
            NUM_OF_BYTES_U256 => ExecutionState::AddU256,
            _ => unreachable!(),
        }
    } else {
        match N_BYTES {
            NUM_OF_BYTES_U8 => ExecutionState::SubU8,
            NUM_OF_BYTES_U16 => ExecutionState::SubU16,
            NUM_OF_BYTES_U32 => ExecutionState::SubU32,
            NUM_OF_BYTES_U64 => ExecutionState::SubU64,
            NUM_OF_BYTES_U128 => ExecutionState::SubU128,
            NUM_OF_BYTES_U256 => ExecutionState::SubU256,
            _ => unreachable!(),
        }
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let mut add_gadget = None;

        // TODO: pass type info with operand
        cb.require_equal(
            "aux0 == N_BYTES",
            step_curr.aux0.expr(),
            (N_BYTES as u64).expr(),
        );

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();

            let add = AddGadget::<_, N_BYTES, ADD>::construct(cb, lhs, rhs, out);
            cb.condition(add.overflow(), |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
            add_gadget = Some(add);
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Add { add_gadget }
    }
}
