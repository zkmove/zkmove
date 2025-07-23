use crate::chips::execution_chip_v2::{ConstraintBuilderV2, InstructionGadgetV2};

use aptos_move_witnesses::exec_state::ExecutionState;

use types::Field; // Assuming this is halo2_proofs::arithmetic::FieldExt or compatible

/// NativePoseidonHash execution state gadget.

/// module poseidon_hash {
///     public native fun hash(input1: u256, input2: u256) -> u256;
/// }

pub struct NativePoseidonHash<F: Field> {
    phantom_: std::marker::PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for NativePoseidonHash<F> {
    const NAME: &'static str = "NativePoseidonHash";
    const EXECUTION_STATE: ExecutionState = ExecutionState::NativePoseidonHash;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        Self {
            phantom_: std::marker::PhantomData,
        }
    }
}
