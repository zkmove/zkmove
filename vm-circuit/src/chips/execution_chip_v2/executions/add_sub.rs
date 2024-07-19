use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::add::AddGadget;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::range_check::IntegerRangeCheck;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::step_state::StageState;
use aptos_move_witnesses::utils::SubIndexUtils;
use halo2_proofs::{circuit::Value, plonk::Error};
use move_core_types::{u256, u256::U256};
use move_vm_runtime::witnessing::traced_value::Integer;
use types::Field;

#[derive(Clone, Debug)]
pub struct AddSub<F> {
    range_check_lo_opt: Option<IntegerRangeCheck<F>>,
    range_check_hi_opt: Option<IntegerRangeCheck<F>>,
    add_opt: Option<AddGadget<F>>,
    is_add_opt: Option<IsZeroGadget<F>>,
    is_u8_opt: Option<IsZeroGadget<F>>,
    is_u16_opt: Option<IsZeroGadget<F>>,
    is_u32_opt: Option<IsZeroGadget<F>>,
    is_u64_opt: Option<IsZeroGadget<F>>,
    is_u128_opt: Option<IsZeroGadget<F>>,
    is_u256_opt: Option<IsZeroGadget<F>>,
    overflow_opt: Option<Cell<F>>,
}
impl<F: Field> InstructionGadgetV2<F> for AddSub<F> {
    const NAME: &'static str = "AddSub";
    const OPCODES: &'static [Opcode] = &[Opcode::Add, Opcode::Sub];
    const EXECUTION_STATE: ExecutionState = ExecutionState::AddSub;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let mut range_check_lo_opt = None;
        let mut range_check_hi_opt = None;
        let mut add_opt = None;
        let mut is_add_opt = None;
        let mut is_u8_opt = None;
        let mut is_u16_opt = None;
        let mut is_u32_opt = None;
        let mut is_u64_opt = None;
        let mut is_u128_opt = None;
        let mut is_u256_opt = None;
        let mut overflow_opt = None;

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

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
            let range_check_lo = IntegerRangeCheck::construct(cb);
            let range_check_hi = IntegerRangeCheck::construct(cb);
            let add = AddGadget::construct(cb);
            let is_add =
                IsZeroGadget::construct(cb, step_curr.opcode.expr() - (Opcode::Add as u64).expr());
            let is_u8 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U8 as u64).expr(),
            );
            let is_u16 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U16 as u64).expr(),
            );
            let is_u32 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U32 as u64).expr(),
            );
            let is_u64 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U64 as u64).expr(),
            );
            let is_u128 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U128 as u64).expr(),
            );
            let is_u256 = IsZeroGadget::construct(
                cb,
                step_curr.aux0.expr() - (NUM_OF_BYTES_U256 as u64).expr(),
            );
            let overflow = cb.query_bool();

            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
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
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            // configure add gadget

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();
            add.expr(cb, lhs, rhs, out.clone(), is_add.expr());

            // overflow check

            // U8,U16,U32,U64
            cb.require_zero(
                "out_hi == 0",
                (is_u8.expr() + is_u16.expr() + is_u32.expr() + is_u64.expr()) * out.hi(),
            );
            cb.condition(is_u8.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U8);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u16.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U16);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u32.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U32);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });
            cb.condition(is_u64.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U64);
                cb.require_equal(
                    "overflow == !in_range(out_lo)",
                    overflow.expr(),
                    1u64.expr() - in_range,
                );
            });

            // U128
            cb.condition(is_u128.expr(), |cb| {
                let in_range = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U128);
                cb.require_true("out_lo < 2^128", in_range);
                //OVERFLOW if out_hi == 1
                cb.require_in_set(
                    "out_hi == 0 | 1",
                    out.hi(),
                    (0u64..2).map(|v| v.expr()).collect(),
                );
                cb.require_equal("overflow == out_hi", overflow.expr(), out.hi());
            });

            // U256
            cb.condition(is_u256.expr(), |cb| {
                let in_range_lo = range_check_lo.expr(cb, out.lo(), NUM_OF_BYTES_U128);
                let in_range_hi = range_check_hi.expr(cb, out.hi(), NUM_OF_BYTES_U128);
                cb.require_true("out_lo < 2^128", in_range_lo);
                cb.require_true("out_hi < 2^128", in_range_hi);
                cb.require_equal(
                    "overflow == add_gadget.overflow()",
                    overflow.expr(),
                    add.overflow(),
                );
            });

            cb.condition(overflow.expr(), |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);

            range_check_lo_opt = Some(range_check_lo);
            range_check_hi_opt = Some(range_check_hi);
            add_opt = Some(add);
            is_add_opt = Some(is_add);
            is_u8_opt = Some(is_u8);
            is_u16_opt = Some(is_u16);
            is_u32_opt = Some(is_u32);
            is_u64_opt = Some(is_u64);
            is_u128_opt = Some(is_u128);
            is_u256_opt = Some(is_u256);
            overflow_opt = Some(overflow);
        });

        AddSub {
            range_check_lo_opt,
            range_check_hi_opt,
            add_opt,
            is_add_opt,
            is_u8_opt,
            is_u16_opt,
            is_u32_opt,
            is_u64_opt,
            is_u128_opt,
            is_u256_opt,
            overflow_opt,
        }
    }

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        debug_assert_eq!(step_state.memory_ops.len(), 1);
        let is_add = if step_state.step_state.opcode == Opcode::Add as u16 {
            true
        } else {
            false
        };
        let num_bytes = step_state.step_state.aux0 as usize;
        let rhs = step_state.memory_ops[0].0.clone().unwrap().value;
        let lhs = step_state.memory_ops[1].0.clone().unwrap().value;
        let out = step_state.memory_ops[1].1.clone().unwrap().value;
        let (rhs_lo, rhs_hi) = Integer::try_from(rhs).unwrap().into();
        let (lhs_lo, lhs_hi) = Integer::try_from(lhs).unwrap().into();
        let (out_lo, out_hi) = Integer::try_from(out).unwrap().into();

        //NOTICE: No private cells in the first row, only assign the second row.
        let offset = offset + 1;
        self.is_add_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(step_state.step_state.opcode as u64) - F::from(Opcode::Add as u64),
        )?;
        self.is_u8_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U8 as u64),
        )?;
        self.is_u16_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U16 as u64),
        )?;
        self.is_u32_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U32 as u64),
        )?;
        self.is_u64_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U64 as u64),
        )?;
        self.is_u128_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U128 as u64),
        )?;
        self.is_u256_opt.clone().unwrap().assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U256 as u64),
        )?;
        self.add_opt.clone().unwrap().assign(
            region, offset, lhs_lo, lhs_hi, rhs_lo, rhs_hi, out_lo, out_hi, is_add,
        )?;

        match num_bytes {
            NUM_OF_BYTES_U8 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U8,
                )?;
                debug_assert!(out_hi == 0u128);
                let overflow = if out_lo > u8::MAX as u128 {
                    F::one()
                } else {
                    F::zero()
                };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            NUM_OF_BYTES_U16 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U16,
                )?;
                debug_assert!(out_hi == 0u128);
                let overflow = if out_lo > u16::MAX as u128 {
                    F::one()
                } else {
                    F::zero()
                };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            NUM_OF_BYTES_U32 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U32,
                )?;
                debug_assert!(out_hi == 0u128);
                let overflow = if out_lo > u32::MAX as u128 {
                    F::one()
                } else {
                    F::zero()
                };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            NUM_OF_BYTES_U64 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U64,
                )?;
                debug_assert!(out_hi == 0u128);
                let overflow = if out_lo > u64::MAX as u128 {
                    F::one()
                } else {
                    F::zero()
                };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            NUM_OF_BYTES_U128 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U128,
                )?;
                debug_assert!(out_hi == 0u128 || out_hi == 1u128);
                let overflow = if out_hi == 1u128 { F::one() } else { F::zero() };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            NUM_OF_BYTES_U256 => {
                self.range_check_lo_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_lo),
                    NUM_OF_BYTES_U128,
                )?;
                self.range_check_hi_opt.clone().unwrap().assign(
                    region,
                    offset,
                    F::from_u128(out_hi),
                    NUM_OF_BYTES_U128,
                )?;
                let lhs_lo = U256::from(lhs_lo);
                let lhs_hi = U256::from(lhs_hi);
                let rhs_lo = U256::from(rhs_lo);
                let rhs_hi = U256::from(rhs_hi);
                let out_lo = U256::from(out_lo);
                let out_hi = U256::from(out_hi);
                let carry_lo = if is_add {
                    (lhs_lo + rhs_lo - out_lo).checked_shr(128).unwrap()
                } else {
                    (out_lo + rhs_lo - lhs_lo).checked_shr(128).unwrap()
                };
                debug_assert!(carry_lo == U256::zero() || carry_lo == U256::one());
                let carry_hi = if is_add {
                    (lhs_hi + rhs_hi + carry_lo - out_hi)
                        .checked_shr(128)
                        .unwrap()
                } else {
                    (out_hi + rhs_hi + carry_lo - lhs_hi)
                        .checked_shr(128)
                        .unwrap()
                };
                debug_assert!(carry_hi == U256::zero() || carry_hi == U256::one());
                let overflow = if carry_hi == U256::one() {
                    F::one()
                } else {
                    F::zero()
                };
                self.overflow_opt.clone().unwrap().assign(
                    region,
                    offset,
                    Value::known(overflow),
                )?;
            }
            _ => unreachable!(),
        }

        Ok(step_state.memory_ops.len())
    }
}
