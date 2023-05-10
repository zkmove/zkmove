use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepConfig;
use crate::chips::execution_chip::utils::CellType;
use crate::chips::utilities::Cell;
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

pub(crate) struct ConstraintBuilder<F: FieldExt> {
    pub(crate) curr: StepConfig<F>,
    pub(crate) next: StepConfig<F>,
    constraints: Vec<(&'static str, Expression<F>)>,
    in_next_step: bool,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(curr: StepConfig<F>, next: StepConfig<F>, _opcode: Opcode) -> Self {
        Self {
            curr,
            next,
            constraints: Vec::new(),
            in_next_step: false,
        }
    }

    pub(crate) fn build(self) -> (Vec<(&'static str, Expression<F>)>, usize) {
        (
            //mul_exec_state_sel(self.constraints),
            self.constraints,
            self.curr.cell_manager.get_height(),
        )
    }

    pub(crate) fn alloc_cell(&mut self) -> Cell<F> {
        self.alloc_cell_with_type(CellType::CustomGate)
    }

    pub(crate) fn alloc_n_cells(&mut self, count: usize) -> Vec<Cell<F>> {
        self.alloc_cells(CellType::CustomGate, count)
    }

    pub(crate) fn alloc_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.alloc_cells(cell_type, 1).first().unwrap().clone()
    }

    fn alloc_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        if self.in_next_step {
            &mut self.next
        } else {
            &mut self.curr
        }
        .cell_manager
        .allocate_cells(cell_type, count)
    }

    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.push_constraint(name, constraint);
    }

    /// TODO: Doc
    fn push_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints.push((name, constraint));
    }
}
