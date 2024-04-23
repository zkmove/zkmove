use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use std::marker::ConstParamTy;
use std::marker::PhantomData;
use types::Field;

#[derive(ConstParamTy, Eq, PartialEq)]
pub enum LdType {
    LdU8,
    LdU16,
    LdU32,
    LdU64,
    LdU128,
    LdTrue,
    LdFalse,
}

#[derive(Clone, Debug)]
pub struct Ld<F, const LD_TYPE: LdType> {
    phantom_data: PhantomData<F>,
}
impl<F: Field, const LD_TYPE: LdType> InstructionGadgetV2<F> for Ld<F, LD_TYPE> {
    const NAME: &'static str = match LD_TYPE {
        LdType::LdU8 => "LdU8",
        LdType::LdU16 => "LdU16",
        LdType::LdU32 => "LdU32",
        LdType::LdU64 => "LdU64",
        LdType::LdU128 => "LdU128",
        LdType::LdTrue => "LdTrue",
        LdType::LdFalse => "LdFalse",
    };

    const OPCODE: Opcode = match LD_TYPE {
        LdType::LdU8 => Opcode::LdU8,
        LdType::LdU16 => Opcode::LdU16,
        LdType::LdU32 => Opcode::LdU32,
        LdType::LdU64 => Opcode::LdU64,
        LdType::LdU128 => Opcode::LdU128,
        LdType::LdTrue => Opcode::LdTrue,
        LdType::LdFalse => Opcode::LdFalse,
    };
    const EXECUTION_STATE: ExecutionState = match LD_TYPE {
        LdType::LdU8 => ExecutionState::LdU8,
        LdType::LdU16 => ExecutionState::LdU16,
        LdType::LdU32 => ExecutionState::LdU32,
        LdType::LdU64 => ExecutionState::LdU64,
        LdType::LdU128 => ExecutionState::LdU128,
        LdType::LdTrue => ExecutionState::LdTrue,
        LdType::LdFalse => ExecutionState::LdFalse,
    };

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        cb.first_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) + 1", Self::NAME),
                cb.curr.state.stack_push_index.expr(),
                cb.curr.state.sp.expr() + 1u64.expr(),
            );

            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                cb.curr.state.stack_push_sub_index.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_value(0) == aux0(0)", Self::NAME),
                cb.curr.state.stack_push_value.expr(),
                cb.curr.state.aux0.expr(),
            );

            cb.require_true(
                format!(
                    "{}, stack_push_value_header(0) == false",
                    Self::NAME
                ),
                1u64.expr() - cb.curr.state.stack_push_value_header.expr(),
            );

            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                cb.curr.state.stack_push_version.expr(),
                cb.curr.state.clk.expr(),
            );

            //TODO: super::common::fake_local_read_zero();

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta(1.expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Ld {
            phantom_data: PhantomData,
        }
    }
}
