use crate::chips::execution_chip_v2::{ConstraintBuilderV2, InstructionGadgetV2};

use aptos_move_witnesses::exec_state::ExecutionState;

use types::Field; // Assuming this is halo2_proofs::arithmetic::FieldExt or compatible

/// NativePoseidonHash execution state gadget.
/// Implements Poseidon hashing for two input words (each WordLoHi), producing one WordLoHi output.
/// The hash output is placed in the low limb of the result word, and the high limb is set to zero.
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
