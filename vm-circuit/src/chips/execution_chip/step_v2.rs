use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::STEP_CHIP_WIDTH;
use crate::chips::execution_chip::utils::dynamic_selector_half::DynamicSelectorHalf;
use crate::chips::execution_chip::utils::{CellManager, CellType};
use crate::chips::utilities::Cell;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Expression};
use types::Field;

#[derive(Clone, Debug)]
pub struct StepState<F> {
    pub clk: Cell<F>,
    pub frame_index: Cell<F>,
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub pc: Cell<F>,
    pub sp: Cell<F>,
    pub opcode: Cell<F>,
    pub aux0: Cell<F>,
    pub aux1: Cell<F>,
    pub step_counter: Cell<F>,

    pub stack_pop_index: Cell<F>,
    pub stack_pop_sub_index: Cell<F>,
    pub stack_pop_value: Cell<F>,
    pub stack_pop_value_flag: Cell<F>,
    pub stack_pop_version: Cell<F>,

    pub stack_push_index: Cell<F>,
    pub stack_push_sub_index: Cell<F>,
    pub stack_push_value: Cell<F>,
    pub stack_push_value_flag: Cell<F>,
    pub stack_push_version: Cell<F>,

    pub local_frame_index: Cell<F>,
    pub local_index: Cell<F>,
    pub local_sub_index: Cell<F>,
    pub local_read_value: Cell<F>,
    pub local_read_value_flag: Cell<F>,
    pub local_read_version: Cell<F>,

    pub local_write_value: Cell<F>,
    pub local_write_value_flag: Cell<F>,
    pub local_write_version: Cell<F>,

    /// The execution state selector for the step
    pub(crate) conditions: DynamicSelectorHalf<F>,
}
#[derive(Debug, Clone)]
pub struct Step<F> {
    pub state: StepState<F>,
    pub cell_manager: CellManager<F>,
}

impl<F: Field> Step<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        offset: isize,
    ) -> Self {
        // height should always be 1
        let mut cell_manager = CellManager::new(meta, 1, &advices, offset);
        let state = StepState {
            clk: cell_manager.alloc_cell(CellType::CustomGate),
            frame_index: cell_manager.alloc_cell(CellType::CustomGate),
            module_index: cell_manager.alloc_cell(CellType::CustomGate),
            function_index: cell_manager.alloc_cell(CellType::CustomGate),
            pc: cell_manager.alloc_cell(CellType::CustomGate),
            sp: cell_manager.alloc_cell(CellType::CustomGate),
            opcode: cell_manager.alloc_cell(CellType::CustomGate),
            aux0: cell_manager.alloc_cell(CellType::CustomGate),
            aux1: cell_manager.alloc_cell(CellType::CustomGate),
            step_counter: cell_manager.alloc_cell(CellType::CustomGate),

            stack_pop_index: cell_manager.alloc_cell(CellType::CustomGate),
            stack_pop_sub_index: cell_manager.alloc_cell(CellType::CustomGate),
            stack_pop_value: cell_manager.alloc_cell(CellType::CustomGate),
            stack_pop_value_flag: cell_manager.alloc_cell(CellType::CustomGate),
            stack_pop_version: cell_manager.alloc_cell(CellType::CustomGate),

            stack_push_index: cell_manager.alloc_cell(CellType::CustomGate),
            stack_push_sub_index: cell_manager.alloc_cell(CellType::CustomGate),
            stack_push_value: cell_manager.alloc_cell(CellType::CustomGate),
            stack_push_value_flag: cell_manager.alloc_cell(CellType::CustomGate),
            stack_push_version: cell_manager.alloc_cell(CellType::CustomGate),

            local_frame_index: cell_manager.alloc_cell(CellType::CustomGate),
            local_index: cell_manager.alloc_cell(CellType::CustomGate),
            local_sub_index: cell_manager.alloc_cell(CellType::CustomGate),
            local_read_value: cell_manager.alloc_cell(CellType::CustomGate),
            local_read_value_flag: cell_manager.alloc_cell(CellType::CustomGate),
            local_read_version: cell_manager.alloc_cell(CellType::CustomGate),
            local_write_value: cell_manager.alloc_cell(CellType::CustomGate),
            local_write_value_flag: cell_manager.alloc_cell(CellType::CustomGate),
            local_write_version: cell_manager.alloc_cell(CellType::CustomGate),

            conditions: DynamicSelectorHalf::new(&mut cell_manager, Opcode::total_numbers()),
        };
        Self {
            state,
            cell_manager,
        }
    }

    pub(crate) fn execution_state_selector(
        &self,
        execution_states: impl IntoIterator<Item = Opcode>,
    ) -> Expression<F> {
        self.state
            .conditions
            .selector(execution_states.into_iter().map(|s| s as usize))
    }
}
