use crate::chips::execution_chip_v2::InstructionGadgetV2;
use aptos_move_witnesses::exec_state::ExecutionState;
use types::Field;

/// NativePoseidonHash execution state gadget.
/// This gadget is used to handle the Poseidon hash function natively within the execution state.
/// It is a placeholder for the Poseidon hash logic and does not implement any specific constraints or logic yet.
/// It can be extended in the future to include specific Poseidon hash constraints if needed.
pub struct NativePoseidonHash<F> {
    phantom_: std::marker::PhantomData<F>,
}

impl<F: Field> InstructionGadgetV2<F> for NativePoseidonHash<F> {
    const NAME: &'static str = "NativePoseidonHash";
    const EXECUTION_STATE: ExecutionState = ExecutionState::NativePoseidonHash;
    fn configure(_cb: &mut crate::chips::execution_chip_v2::ConstraintBuilderV2<F>) -> Self {
        // Configuration logic for NativePoseidonHash can be added here if needed
        Self {
            phantom_: std::marker::PhantomData,
        }
    }
}
