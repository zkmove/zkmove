use crate::chips::execution_chip_v2::executions::bitwise::to_nibbles::ToNibbles;
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::step_v2::{StepState, PC, SP};
use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::{
    ConstraintBuilderV2, Transition,
};
use crate::chips::execution_chip_v2::utils::from_limbs;
use crate::chips::execution_chip_v2::value::{NUM_OF_BYTES_U256, NUM_OF_NIBBLE_U256};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utils::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::{StageExtraAssignData, StageState};
use aptos_move_witnesses::utils::to_u256::ToU256;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use itertools::{izip, Itertools};
use std::marker::PhantomData;
use types::Field;
#[derive(Clone, Debug)]
pub struct BitwiseStage1<F, const R: usize, const C: usize> {
    lhs_nibbles: [Cell<F>; C],
    rhs_nibbles: [Cell<F>; C],
    out_nibbles: [Cell<F>; C],
}
impl<F: Field, const R: usize, const C: usize> InstructionGadgetV2<F> for BitwiseStage1<F, R, C> {
    const NAME: &'static str = "BitwiseStage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::BitwiseStage1;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        debug_assert_eq!(R * C, NUM_OF_NIBBLE_U256);
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let lhs_nibbles = cb.query_cells::<C>();
        let rhs_nibbles = cb.query_cells::<C>();
        let out_nibbles = cb.query_cells::<C>();

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
        });

        // stack pop
        cb.require_equal(
            format!(
                "{}, stack_pop_index(0) == sp(0) + step_counter(0) - 2",
                Self::NAME
            ),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr() + step_curr.step_counter.expr() - 2u64.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );

        cb.first_row(|cb| {
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_push_index(0) == stack_pop_index", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.stack_pop_index.expr(),
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
        });

        cb.last_row(|cb| {
            // constrain lhs
            let lhs = step_curr.stack_pop_value.as_integer();
            let nibbles_lhs = (1..(R as i32))
                .flat_map(|i| cb.cells_at_offset(lhs_nibbles.clone(), i))
                .collect::<Vec<_>>();
            cb.require_equal(
                "lhs.lo = from_limbs(nibbles_lhs[0..32])",
                lhs.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles_lhs[..NUM_OF_BYTES_U256]),
            );
            cb.require_equal(
                "lhs.hi = from_limbs(nibbles_lhs[32..])",
                lhs.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles_lhs[NUM_OF_BYTES_U256..]),
            );

            // constrain rhs
            let rhs = step_prev.stack_pop_value.as_integer();
            let nibbles_rhs = (1..(R as i32))
                .flat_map(|i| cb.cells_at_offset(rhs_nibbles.clone(), i))
                .collect::<Vec<_>>();
            cb.require_equal(
                "rhs.lo = from_limbs(nibbles_rhs[0..32])",
                rhs.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles_rhs[..NUM_OF_BYTES_U256]),
            );
            cb.require_equal(
                "rhs.hi = from_limbs(nibbles_rhs[32..])",
                rhs.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles_rhs[NUM_OF_BYTES_U256..]),
            );

            // constrain output
            let out = step_curr.stack_push_value.as_integer();
            let nibbles_out = (1..(R as i32))
                .flat_map(|i| cb.cells_at_offset(out_nibbles.clone(), i))
                .collect::<Vec<_>>();

            cb.require_equal(
                "out.lo = from_limbs(nibbles[0..32])",
                out.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles_out[..NUM_OF_BYTES_U256]),
            );
            cb.require_equal(
                "out.hi = from_limbs(nibbles[32..])",
                out.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles_out[NUM_OF_BYTES_U256..]),
            );
        });
        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::BitwiseStage2);
            // only need to make sure pc, sp are the same
            cb.require_state_transition(
                [PC, SP]
                    .into_iter()
                    .map(|state_name| (state_name, Transition::Same))
                    .collect(),
            );
        });
        BitwiseStage1 {
            lhs_nibbles,
            rhs_nibbles,
            out_nibbles,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        // debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        Ok(step_state.memory_ops.len())
    }
}

#[derive(Clone, Debug)]
pub struct BitwiseStage2<F, const R: usize, const C: usize> {
    lhs_nibbles: [Cell<F>; C],
    rhs_nibbles: [Cell<F>; C],
    out_nibbles: [Cell<F>; C],
}
impl<F: Field, const R: usize, const C: usize> InstructionGadgetV2<F> for BitwiseStage2<F, R, C> {
    const NAME: &'static str = "BitwiseStage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::BitwiseStage2;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        debug_assert_eq!(R * C, NUM_OF_NIBBLE_U256);
        let step_curr = cb.curr.state.clone();
        let lhs_nibbles = cb.query_cells::<C>();
        let rhs_nibbles = cb.query_cells::<C>();
        let out_nibbles = cb.query_cells::<C>();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::BitwiseStage1);

            // NOTICE: not necessary needed.
            // cb.require_in_set(
            //     "opcode in OPCODES",
            //     step_curr.opcode.expr(),
            //     Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            // );

            cb.require_equal(
                "step_counter(0) == R",
                step_curr.step_counter.expr(),
                R.expr(),
            );
        });

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        let op = BitwiseOperation {
            opcode: step_curr.opcode.expr(),
            nibbles_lhs: lhs_nibbles.clone(),
            nibbles_rhs: rhs_nibbles.clone(),
            nibbles_out: out_nibbles.clone(),
        };
        LookupBitwise::lookup(cb, op);

        cb.last_row(|cb| {
            cb.require_state_transition(vec![
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        BitwiseStage2 {
            lhs_nibbles,
            rhs_nibbles,
            out_nibbles,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        // debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();

        debug_assert_eq!(step_state.memory_ops.len(), R);
        let (lhs, rhs, out) = match &stage_state.extra_data {
            Some(StageExtraAssignData::BitWise(d)) => (d.lhs, d.rhs, d.out),
            _ => unreachable!(),
        };
        for (cells, value) in [
            (&self.rhs_nibbles, rhs),
            (&self.lhs_nibbles, lhs),
            (&self.out_nibbles, out),
        ] {
            for (i, chunk) in value
                .to_nibbles()
                .as_chunks::<C>()
                .0
                .iter()
                .cloned()
                .enumerate()
            {
                for (cell, nibble) in cells.iter().zip_eq(chunk) {
                    cell.assign(region, offset + i, Value::known(F::from(nibble as u64)))?;
                }
            }
        }

        Ok(step_state.memory_ops.len())
    }
}
#[derive(Clone, Debug)]
pub struct Bitwise<F> {
    nibbles: [Cell<F>; NUM_OF_BYTES_U256 * 2],
}
impl<F: Field> InstructionGadgetV2<F> for Bitwise<F> {
    const NAME: &'static str = "Bitwise";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Bitwise;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let step_prev_2 = cb.step_state_at_offset(-2);
        // although we use byte to represent nibble, no need to do range check as these cells will be bitwise-lookuped.
        let nibbles: [Cell<F>; NUM_OF_NIBBLE_U256] = cb.query_bytes::<NUM_OF_NIBBLE_U256>();

        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                "step_counter(0) == 3",
                step_curr.step_counter.expr(),
                3u64.expr(),
            );
        });

        cb.not_last_row(|cb| {
            cb.require_equal(
                format!(
                    "{}, stack_pop_index(0) == sp(0) + step_counter(0) - 3",
                    Self::NAME
                ),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() + step_curr.step_counter.expr() - 3u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
                step_curr.stack_pop_sub_index.expr(),
            );
            cb.require_zero(
                format!("{}, stack_pop_value_header(0) == false", Self::NAME),
                step_curr.stack_pop_value_header.expr(),
            );
            cb.require_no_stack_push();
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_no_stack_pop();

            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            // constrain lhs
            let lhs = step_prev.stack_pop_value.as_integer();
            let nibbles_lhs = nibbles.clone().map(|cell| cb.cell_at_offset(&cell, -1));
            cb.require_equal(
                "lhs.lo = from_limbs(nibbles_lhs[0..32])",
                lhs.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles_lhs[..32]),
            );
            cb.require_equal(
                "lhs.hi = from_limbs(nibbles_lhs[32..])",
                lhs.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles_lhs[32..]),
            );

            // constrain rhs
            let rhs = step_prev_2.stack_pop_value.as_integer();
            let nibbles_rhs = nibbles.clone().map(|cell| cb.cell_at_offset(&cell, -2));
            cb.require_equal(
                "rhs.lo = from_limbs(nibbles_rhs[0..32])",
                rhs.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles_rhs[..32]),
            );
            cb.require_equal(
                "rhs.hi = from_limbs(nibbles_rhs[32..])",
                rhs.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles_rhs[32..]),
            );

            // constrain output
            let out = step_curr.stack_push_value.as_integer();
            cb.require_equal(
                "out.lo = from_limbs(nibbles[0..32])",
                out.lo(),
                from_limbs::expr::<_, _, 4>(&nibbles[..32]),
            );
            cb.require_equal(
                "out.hi = from_limbs(nibbles[32..])",
                out.hi(),
                from_limbs::expr::<_, _, 4>(&nibbles[32..]),
            );

            let op = BitwiseOperation {
                opcode: step_curr.opcode.expr(),
                nibbles_lhs,
                nibbles_rhs,
                nibbles_out: nibbles.clone(),
            };
            LookupBitwise::lookup(cb, op);
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                "stack_push_version(0) == clk(0)",
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Bitwise { nibbles }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let rhs_word = step_state.memory_ops[0].0.clone().unwrap().value;
        let lhs_word = step_state.memory_ops[1].0.clone().unwrap().value;
        let out_word = step_state.memory_ops[2].1.clone().unwrap().value;
        let rhs = rhs_word.to_u256();
        let lhs = lhs_word.to_u256();
        let out = out_word.to_u256();

        debug_assert_eq!(step_state.memory_ops.len(), 3);
        for (cell, nibble) in izip!(self.nibbles.clone(), rhs.to_nibbles()) {
            cell.assign(region, offset, Value::known(F::from(nibble as u64)))?;
        }
        for (cell, nibble) in izip!(self.nibbles.clone(), lhs.to_nibbles()) {
            cell.assign(region, offset + 1, Value::known(F::from(nibble as u64)))?;
        }
        for (cell, nibble) in izip!(self.nibbles.clone(), out.to_nibbles()) {
            cell.assign(region, offset + 2, Value::known(F::from(nibble as u64)))?;
        }
        Ok(step_state.memory_ops.len())
    }
}

struct BitwiseOperation<F: Field, const C: usize> {
    opcode: Expression<F>,
    nibbles_lhs: [Cell<F>; C],
    nibbles_rhs: [Cell<F>; C],
    nibbles_out: [Cell<F>; C],
}

struct LookupBitwise<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> LookupBitwise<F> {
    fn lookup<const C: usize>(cb: &mut ConstraintBuilderV2<F>, op: BitwiseOperation<F, C>) {
        for (operand_1, operand_2, result) in izip!(op.nibbles_lhs, op.nibbles_rhs, op.nibbles_out)
        {
            cb.add_lookup_directly(
                "bitwise lookup".to_string(),
                Lookup::Bitwise {
                    opcode: op.opcode.clone(),
                    value_1: operand_1.expr(),
                    value_2: operand_2.expr(),
                    result: result.expr(),
                },
            );
        }
    }
}

pub mod to_nibbles {
    use crate::chips::execution_chip_v2::value::NUM_OF_BYTES_U256;
    use move_core_types::u256::U256;

    // Convert to half-byte array in little-endian order
    pub trait ToNibbles {
        fn to_nibbles(&self) -> [u8; NUM_OF_BYTES_U256 * 2];
    }

    impl ToNibbles for U256 {
        fn to_nibbles(&self) -> [u8; NUM_OF_BYTES_U256 * 2] {
            let bytes = self.to_le_bytes();
            bytes
                .into_iter()
                .flat_map(|byte| {
                    let lo = byte & 0x0F;
                    let hi = (byte & 0xF0) >> 4;
                    [lo, hi]
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::ToNibbles;
        use move_core_types::u256::U256;

        #[test]
        fn test_to_nibbles() {
            let expected = [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(U256::one().to_nibbles(), expected);

            let expected = [
                0, 0xF, 0, 0xE, 0, 0xF, 0, 0xF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(U256::from(0xF0F0E0F0u32).to_nibbles(), expected);

            let expected = [
                0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(U256::from(u64::MAX as u128).to_nibbles(), expected);
        }
    }
}
