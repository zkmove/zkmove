use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use halo2_proofs::plonk::Error;
use types::Field;

#[derive(Clone, Debug)]
pub struct Cast<F> {
    cast_u8: IsZeroGadget<F>,
    cast_u16: IsZeroGadget<F>,
    cast_u32: IsZeroGadget<F>,
    cast_u64: IsZeroGadget<F>,
    cast_u128: IsZeroGadget<F>,
    cast_u256: IsZeroGadget<F>,
    in_range_lo: IntegerRangeCheck<F>,
    is_zero_hi: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Cast<F> {
    const NAME: &'static str = "Cast";

    const OPCODES: &'static [Opcode] = &[
        Opcode::CastU8,
        Opcode::CastU16,
        Opcode::CastU32,
        Opcode::CastU64,
        Opcode::CastU128,
        Opcode::CastU256,
    ];
    const EXECUTION_STATE: ExecutionState = ExecutionState::Cast;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let cast_u8 =
            IsZeroGadget::construct(cb, step_curr.opcode.expr() - (Opcode::CastU8 as u64).expr());
        let cast_u16 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcode::CastU16 as u64).expr(),
        );
        let cast_u32 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcode::CastU32 as u64).expr(),
        );
        let cast_u64 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcode::CastU64 as u64).expr(),
        );
        let cast_u128 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcode::CastU128 as u64).expr(),
        );
        let cast_u256 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcode::CastU256 as u64).expr(),
        );

        cb.require_in_set(
            "opcode in OPCODES",
            step_curr.opcode.expr(),
            Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
        );
        cb.require_equal(
            "step_counter(0) == 1",
            step_curr.step_counter.expr(),
            1u64.expr(),
        );
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
        cb.require_equal(
            format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
            step_curr.stack_push_index.expr(),
            step_curr.sp.expr(),
        );

        cb.require_zero(
            format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
            step_curr.stack_push_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_push_value_header(0) == false", Self::NAME),
            step_curr.stack_push_value_header.expr(),
        );

        cb.require_no_local_op();

        let in_range_lo = IntegerRangeCheck::construct(cb);
        let hi = step_curr.stack_pop_value.as_integer().hi();
        let lo = step_curr.stack_pop_value.as_integer().lo();
        let is_zero_hi = IsZeroGadget::construct(cb, hi);

        let castable = cast_u8.expr()
            * in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U8)
            * is_zero_hi.expr()
            + cast_u16.expr()
                * in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U16)
                * is_zero_hi.expr()
            + cast_u32.expr()
                * in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U32)
                * is_zero_hi.expr()
            + cast_u64.expr()
                * in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U64)
                * is_zero_hi.expr()
            + cast_u128.expr() * in_range_lo.expr(cb, lo, NUM_OF_BYTES_U128) * is_zero_hi.expr()
            + cast_u256.expr(); //cast_u256 will always be in range

        cb.condition(castable.clone(), |cb| {
            cb.require_equal(
                format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                step_curr.stack_push_value.expr(),
                step_curr.stack_pop_value.expr(),
            );
            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });
        cb.condition(1u64.expr() - castable, |cb| {
            // TODO: error state
            // cb.require_next_state(ExecutionState::ErrorState);
            // ErrorCode == StatusCode::ArithmeticError
        });

        Cast {
            cast_u8,
            cast_u16,
            cast_u32,
            cast_u64,
            cast_u128,
            cast_u256,
            in_range_lo,
            is_zero_hi,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}
