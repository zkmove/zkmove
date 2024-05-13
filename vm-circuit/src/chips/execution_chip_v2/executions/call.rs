use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::executions::ValueHeader;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::Cell;
use gadgets::util::not;
use std::marker::PhantomData;
use types::Field;

#[derive(Clone, Debug)]
pub struct CallWithNoArgs<F> {
    phantom_data: PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for CallWithNoArgs<F> {
    const NAME: &'static str = "CallWithNoArgs";
    const OPCODE: Opcode = Opcode::Call;
    const EXECUTION_STATE: ExecutionState = ExecutionState::CallWithNoArgs;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();

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

        // TODO: add lookup table 'table_func'
        //table_func.contain(aux0(0)/*callee's module_index*/, aux1(0)/*callee's function_index*/, 0/*arg_num(0)==0*/);

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.require_state_transition(vec![
            (SP, Transition::Same),
            (FRAME_INDEX, Transition::Delta(1.expr())),
            (PC, Transition::To(0.expr())),
        ]);

        CallWithNoArgs {
            phantom_data: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CallWithArgs<F: Field> {
    arg_num: Cell<F>,
    header: ValueHeader<F>,
    is_zero_arg_num: IsZeroGadget<F>,
    is_zero_local_index: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for CallWithArgs<F> {
    const NAME: &'static str = "CallWithArgs";
    const OPCODE: Opcode = Opcode::Call;
    const EXECUTION_STATE: ExecutionState = ExecutionState::CallWithArgs;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let arg_num = cb.query_cell();
        let header = ValueHeader::new(cb);
        let is_zero_arg_num = IsZeroGadget::construct(cb, arg_num.expr());
        let is_zero_local_index = IsZeroGadget::construct(cb, cb.curr.state.local_index.expr());
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_equal(
                "opcode",
                step_curr.opcode.expr(),
                (Self::OPCODE as u64).expr(),
            );

            // TODO: add lookup table 'table_func'
            //table_func.contain(aux0(0)/*callee's module_index*/, aux1(0)/*callee's function_index*/, arg_num(0));

            cb.require_false(
                format!("{}, arg_num(0) != 0", Self::NAME),
                is_zero_arg_num.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
            cb.condition(step_curr.stack_pop_value_header.expr(), |cb| {
                cb.require_equal(
                    format!("{}, stack_pop_value(0) == header", Self::NAME),
                    step_curr.stack_pop_value.expr(),
                    header.expr(),
                );
                cb.require_equal(
                    format!("{}, step_counter(0) == header.flen", Self::NAME),
                    step_curr.step_counter.expr(),
                    header.flen.expr(),
                );
            });
            cb.condition(not::expr(step_curr.stack_pop_value_header.expr()), |cb| {
                cb.require_equal(
                    format!("{}, step_counter(0) == 1", Self::NAME),
                    step_curr.step_counter.expr(),
                    1u64.expr(),
                );
            });
            let prev_state = cb.step_state_at_offset(-1);
            let is_prev_state_call_with_args =
                prev_state.execution_state_selector([ExecutionState::CallWithArgs]);
            cb.condition(not::expr(is_prev_state_call_with_args), |cb| {
                cb.require_equal(
                    format!("{}, local_index(0) == arg_num(0) - 1", Self::NAME),
                    step_curr.local_index.expr(),
                    arg_num.expr() - 1u64.expr(),
                );
            });
        });
        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
        cb.require_equal(
            format!("{}, local_frame_index(0) == frame_index(0) + 1", Self::NAME),
            step_curr.local_frame_index.expr(),
            step_curr.frame_index.expr() + 1u64.expr(), //write to local of next frame
        );
        cb.require_equal(
            format!(
                "{}, local_sub_index(0) == stack_pop_sub_index(0)",
                Self::NAME
            ),
            step_curr.local_sub_index.expr(),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, local_read_value(0) == 0", Self::NAME),
            step_curr.local_read_value.expr(),
        );
        cb.require_zero(
            format!("{}, local_read_value_header(0) == 0", Self::NAME),
            step_curr.local_read_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_read_value_invalid == 1", Self::NAME),
            step_curr.local_read_value_invalid.expr(),
            1u64.expr(),
        );
        cb.require_zero(
            format!("{}, local_read_version(0) == 0", Self::NAME),
            step_curr.local_read_version.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_value(0) == stack_pop_value(0)", Self::NAME),
            step_curr.local_write_value.expr(),
            step_curr.stack_pop_value.expr(),
        );
        cb.require_zero(
            format!("{}, local_write_value_invalid == 0", Self::NAME),
            step_curr.local_write_value_invalid.expr(),
        );
        cb.require_equal(
            format!(
                "{}, local_write_value_header(0) == stack_pop_value_header(0)",
                Self::NAME
            ),
            step_curr.local_write_value_header.expr(),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_equal(
            format!("{}, local_write_version(0) == clk(0)", Self::NAME),
            step_curr.local_write_version.expr(),
            step_curr.clk.expr(),
        );
        cb.require_no_stack_push();

        cb.not_last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Same)]);
            cb.require_cell_transition(step_curr.local_index.clone(), Transition::Same);
        });
        cb.last_row(|cb| {
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
            cb.condition(is_zero_local_index.expr(), |cb| {
                //all args have been processed
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Delta(1.expr())),
                    (MODULE_INDEX, Transition::To(aux0(0).expr())),
                    (FUNCTION_INDEX, Transition::To(aux1(0).expr())),
                    (PC, Transition::To(0.expr())),
                ]);
            });
            cb.condition(not::expr(is_zero_local_index.expr()), |cb| {
                cb.require_cell_transition(step_curr.local_index, Transition::Delta((-1).expr()));
                cb.require_next_state(ExecutionState::CallWithArgs);
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Same),
                    (MODULE_INDEX, Transition::Same),
                    (FUNCTION_INDEX, Transition::Same),
                    (PC, Transition::Same),
                ]);
            });
        });

        CallWithArgs {
            arg_num,
            header,
            is_zero_arg_num,
            is_zero_local_index,
        }
    }
}
