use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, PC, SP,
};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utils::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use halo2_proofs::plonk::Error;
use move_binary_format::file_format_common::Opcodes;
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
    overflow: Cell<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Cast<F> {
    const NAME: &'static str = "Cast";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Cast;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let cast_u8 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U8 as u64).expr(),
        );
        let cast_u16 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U16 as u64).expr(),
        );
        let cast_u32 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U32 as u64).expr(),
        );
        let cast_u64 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U64 as u64).expr(),
        );
        let cast_u128 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U128 as u64).expr(),
        );
        let cast_u256 = IsZeroGadget::construct(
            cb,
            step_curr.opcode.expr() - (Opcodes::CAST_U256 as u64).expr(),
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
        cb.require_equal(
            "stack_push_version(0) == clk(0)",
            step_curr.stack_push_version.expr(),
            step_curr.clk.expr(),
        );

        cb.require_no_local_op();

        let in_range_lo = IntegerRangeCheck::construct(cb);
        let hi = step_curr.stack_pop_value.as_integer().hi();
        let lo = step_curr.stack_pop_value.as_integer().lo();
        let is_zero_hi = IsZeroGadget::construct(cb, hi);
        let hi_is_zero = is_zero_hi.expr();
        let overflow = cb.query_bool();

        cb.condition(cast_u8.expr(), |cb| {
            let lo_in_range = in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U8);
            cb.require_equal(
                "!overflow == in_range(lo) && is_zero(hi)",
                1u64.expr() - overflow.expr(),
                lo_in_range * hi_is_zero.clone(),
            );
        });
        cb.condition(cast_u16.expr(), |cb| {
            let lo_in_range = in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U16);
            cb.require_equal(
                "!overflow == in_range(lo) && is_zero(hi)",
                1u64.expr() - overflow.expr(),
                lo_in_range * hi_is_zero.clone(),
            );
        });
        cb.condition(cast_u32.expr(), |cb| {
            let lo_in_range = in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U32);
            cb.require_equal(
                "!overflow == in_range(lo) && is_zero(hi)",
                1u64.expr() - overflow.expr(),
                lo_in_range * hi_is_zero.clone(),
            );
        });
        cb.condition(cast_u64.expr(), |cb| {
            let lo_in_range = in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U64);
            cb.require_equal(
                "!overflow == in_range(lo) && is_zero(hi)",
                1u64.expr() - overflow.expr(),
                lo_in_range * hi_is_zero.clone(),
            );
        });
        cb.condition(cast_u128.expr(), |cb| {
            let lo_in_range = in_range_lo.expr(cb, lo.clone(), NUM_OF_BYTES_U128);
            cb.require_equal(
                "!overflow == in_range(lo) && is_zero(hi)",
                1u64.expr() - overflow.expr(),
                lo_in_range * hi_is_zero,
            );
        });

        //cast_u256 will always be in range

        cb.condition(1u64.expr() - overflow.expr(), |cb| {
            cb.require_equal(
                format!("{}, stack_push_value(0) == stack_pop_value(0)", Self::NAME),
                step_curr.stack_push_value.expr(),
                step_curr.stack_pop_value.expr(),
            );
            cb.require_state_transition(vec![
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });
        cb.condition(overflow.expr(), |cb| {
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
            overflow,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let opcode = step_state.step_state.opcode;
        let num_bytes = if opcode == Opcodes::CAST_U8 as u8 {
            NUM_OF_BYTES_U8
        } else if opcode == Opcodes::CAST_U16 as u8 {
            NUM_OF_BYTES_U16
        } else if opcode == Opcodes::CAST_U32 as u8 {
            NUM_OF_BYTES_U32
        } else if opcode == Opcodes::CAST_U64 as u8 {
            NUM_OF_BYTES_U64
        } else if opcode == Opcodes::CAST_U128 as u8 {
            NUM_OF_BYTES_U128
        } else if opcode == Opcodes::CAST_U256 as u8 {
            NUM_OF_BYTES_U256
        } else {
            unreachable!()
        };
        self.cast_u8.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U8 as u64),
        )?;
        self.cast_u16.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U16 as u64),
        )?;
        self.cast_u32.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U32 as u64),
        )?;
        self.cast_u64.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U64 as u64),
        )?;
        self.cast_u128.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U128 as u64),
        )?;
        self.cast_u256.assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcodes::CAST_U256 as u64),
        )?;

        debug_assert!(!step_state.memory_ops.is_empty());
        let input = step_state.memory_ops[0].0.clone().unwrap().value;
        if opcode == Opcodes::CAST_U256 as u8 {
            self.in_range_lo
                .assign(region, offset, F::from_u128(input.lo()), NUM_OF_BYTES_U128)?;
        } else {
            self.in_range_lo
                .assign(region, offset, F::from_u128(input.lo()), num_bytes)?;
        }
        self.is_zero_hi
            .assign(region, offset, F::from_u128(input.hi()))?;
        Ok(1)
    }
}
