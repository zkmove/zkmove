use crate::chips::execution_chip::lookup_tables::Lookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepConfig;
use crate::chips::execution_chip::utils::CellType;
use crate::chips::utilities::{Cell, Expr};

use fields::FieldExt;
use halo2_proofs::plonk::Expression;

pub(crate) struct ConstraintBuilder<F: FieldExt> {
    opcode: Opcode,
    pub(crate) curr: StepConfig<F>,
    pub(crate) next: StepConfig<F>,
    constraints: Vec<(&'static str, Expression<F>)>,
    conditions: Vec<Expression<F>>,
    lookups: Vec<(&'static str, Lookup<F>)>,
    in_next_step: bool,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(curr: StepConfig<F>, next: StepConfig<F>, opcode: Opcode) -> Self {
        Self {
            opcode,
            curr,
            next,
            constraints: Vec::new(),
            in_next_step: false,
            conditions: Vec::new(),
            lookups: Vec::new(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (
        Vec<(&'static str, Expression<F>)>,
        Vec<(&'static str, Lookup<F>)>,
        usize,
    ) {
        debug_assert_eq!(self.conditions.len(), 0);
        let op_sel = self.curr.cells.opcode_selector([self.opcode]);
        (
            self.constraints
                .into_iter()
                .map(|(name, constraint)| (name, op_sel.clone() * constraint))
                .collect(),
            self.lookups
                .into_iter()
                .map(|(name, lookup)| (name, Lookup::Conditional(op_sel.clone(), Box::new(lookup))))
                .collect(),
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

    // Lookups

    pub(crate) fn add_lookup<L: Into<Lookup<F>>>(&mut self, name: &'static str, lookup: L) {
        let lookup = lookup.into();
        let lookup = match self.condition_expr_opt() {
            Some(c) => Lookup::Conditional(c, Box::new(lookup)),
            None => lookup,
        };
        self.lookups.push((name, lookup))
    }

    // General

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        self.conditions.push(condition);
        let ret = constraint(self);
        self.conditions.pop();
        ret
    }

    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.push_constraint(name, constraint * self.condition_expr());
    }

    fn push_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.constraints.push((name, constraint));
    }

    fn condition_expr_opt(&self) -> Option<Expression<F>> {
        let mut iter = self.conditions.iter();
        let first = match iter.next() {
            Some(e) => e,
            None => return None,
        };
        Some(iter.fold(first.clone(), |acc, e| acc * e.clone()))
    }
    fn condition_expr(&self) -> Expression<F> {
        match self.condition_expr_opt() {
            Some(condition) => condition,
            None => 1.expr(),
        }
    }
}
