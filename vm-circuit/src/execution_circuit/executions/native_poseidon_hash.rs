use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::{InstructionGadgetV2, VmConstraintBuilder};
use crate::lookup_table::Lookup;
use crate::utils::vm_constraint_builder::Transition;
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use witness::native_functions::zkhash::DOMAIN_SPEC;
use witness::static_info::StaticInfo;
use witness::step_state::ExecutionState;
use witness::step_state::StageState;

use crate::public_inputs::InstanceTable;
use field_exts::util::Expr;
use field_exts::Field;
use halo2_proofs::plonk::ErrorFront as Error;
use poseidon_base::Hashable;

/// NativePoseidonHash execution state gadget.
/// Handles the native Poseidon hash function that takes two U128 inputs
/// and produces a U256 hash output.
///
/// Stack operations:
/// - Pops two U128 values (arg1, arg2) from stack
/// - Pushes one U256 hash result to stack
/// - Net effect: SP decreases by 1

#[derive(Clone)]
pub struct NativePoseidonHash<F> {
    phantom_: std::marker::PhantomData<F>,
}

impl<F: Field + Hashable> InstructionGadgetV2<F> for NativePoseidonHash<F> {
    const NAME: &'static str = "NativePoseidonHash";
    const EXECUTION_STATE: ExecutionState = ExecutionState::NativePoseidonHash;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);

        cb.first_row(|cb| {
            // TODO: opcode now is call. should constraint A::M::F to be native_poseidon_hash
            // cb.require_in_set(
            //     format!("{}, opcode in OPCODES", Self::NAME),
            //     step_curr.opcode.expr(),
            //     Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            // );
            cb.require_equal(
                format!("{}, step_counter(0) == 2", Self::NAME),
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();

            // Stack pop constraints - we pop from top of stack (SP)
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
        // Ensure we're popping two U128 values
        // cb.require_equal(
        //     "stack_pop_value should be U128",
        //     step_curr.stack_pop_value.as_u128().num_of_bytes(),
        //     NUM_OF_BYTES_U128.expr(),
        // );

        // No local operations for native hash
        cb.require_no_local_op();

        cb.last_row(|cb| {
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
            let rhs = step_prev.stack_pop_value.as_integer().compress();
            let lhs = step_curr.stack_pop_value.as_integer().compress();
            let result = step_curr.stack_push_value.as_integer().compress();
            cb.add_lookup(
                "poseidon hash lookup",
                Lookup::PoseidonHash {
                    hash_id: result,
                    input0: lhs,
                    input1: rhs,
                    domain_spec: DOMAIN_SPEC.expr(),
                },
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

            // State transitions: PC advances by 1, SP decreases by 1 (2 pops, 1 push)
            cb.require_state_transition(vec![
                (PC, Transition::Delta(1.expr())),
                (SP, Transition::Delta(1.expr() - 2.expr())),
            ]);
        });

        Self {
            phantom_: std::marker::PhantomData,
        }
    }
    fn assign(
        &self,
        _step: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        // The hash computation is handled in the witness preprocessor
        // No additional circuit assignments needed here
        Ok(stage_state.rows())
    }
}
