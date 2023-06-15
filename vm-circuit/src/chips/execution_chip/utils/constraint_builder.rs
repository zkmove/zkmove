use crate::chips::execution_chip::lookup_tables::Lookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepConfig;
use crate::chips::execution_chip::utils::CellType;
use crate::chips::utilities::{Cell, Expr};

use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

pub(crate) struct ConstraintBuilder<F: FieldExt> {
    opcode: Opcode,
    pub(crate) curr: StepConfig<F>,
    pub(crate) next: StepConfig<F>,
    constraints: Vec<(&'static str, ConditionalExpression<F>)>,
    conditions: Vec<Expression<F>>,
    lookups: Vec<(&'static str, ConditionalLookup<F>)>,
    in_next_step: bool,
}

pub struct ConditionalConstraint<F, T> {
    conds: Vec<Expression<F>>,
    expr: T,
}

impl<F, T> ConditionalConstraint<F, T> {
    pub fn new(constraint: T) -> Self {
        Self::with_conditions(vec![], constraint)
    }
    pub fn with_conditions(conds: Vec<Expression<F>>, constraint: T) -> Self {
        Self {
            conds,
            expr: constraint,
        }
    }

    pub fn add_conditions(&mut self, mut conds: Vec<Expression<F>>) {
        self.conds.append(&mut conds);
    }
}

impl<F, T> From<ConditionalConstraint<F, T>> for (Vec<Expression<F>>, T) {
    fn from(c: ConditionalConstraint<F, T>) -> Self {
        (c.conds, c.expr)
    }
}

impl<F, T> AsRef<T> for ConditionalConstraint<F, T> {
    fn as_ref(&self) -> &T {
        &self.expr
    }
}

pub type ConditionalExpression<F> = ConditionalConstraint<F, Expression<F>>;
pub type ConditionalLookup<F> = ConditionalConstraint<F, Lookup<F>>;

impl<F: FieldExt> Expr<F> for ConditionalExpression<F> {
    fn expr(&self) -> Expression<F> {
        match mul_exprs(&self.conds) {
            Some(c) => c * self.expr.clone(),
            None => self.expr.clone(),
        }
    }
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
        Vec<(&'static str, ConditionalExpression<F>)>,
        Vec<(&'static str, ConditionalLookup<F>)>,
        usize,
    ) {
        debug_assert_eq!(self.conditions.len(), 0);
        let op_sel = self.curr.cells.opcode_selector([self.opcode]);
        (
            self.constraints
                .into_iter()
                .map(|(name, mut constraint)| {
                    constraint.add_conditions(vec![op_sel.clone()]);
                    (name, constraint)
                })
                .collect(),
            self.lookups
                .into_iter()
                .map(|(name, mut lookup)| {
                    lookup.add_conditions(vec![op_sel.clone()]);
                    (name, lookup)
                })
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
        let lookup = ConditionalLookup::with_conditions(self.conditions.clone(), lookup);
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
        self.push_constraint(name, self.conditions.clone(), constraint);
    }

    fn push_constraint(
        &mut self,
        name: &'static str,
        conds: Vec<Expression<F>>,
        constraint: Expression<F>,
    ) {
        self.constraints.push((
            name,
            ConditionalExpression::with_conditions(conds, constraint),
        ));
    }

    #[allow(dead_code)]
    fn condition_expr_opt(&self) -> Option<Expression<F>> {
        let mut iter = self.conditions.iter();
        let first = match iter.next() {
            Some(e) => e,
            None => return None,
        };
        Some(iter.fold(first.clone(), |acc, e| acc * e.clone()))
    }
}

pub fn mul_exprs<F: FieldExt>(iter: impl AsRef<[Expression<F>]>) -> Option<Expression<F>> {
    let mut iter = iter.as_ref().iter();
    let first = match iter.next() {
        Some(e) => e,
        None => return None,
    };
    Some(iter.fold(first.clone(), |acc, e| acc * e.clone()))
}

// pub fn mul_exprs<F: FieldExt>(iter: impl AsRef<[Expression<F>]>) -> Option<Expression<F>> {
//     //let mut iter = self.conditions.iter();
//     let iter = iter.as_ref();
//     if iter.is_empty() {
//         None
//     } else if iter.len() == 1 {
//         Some(iter[0].clone())
//     } else {
//         let (left, right) = iter.split_at(iter.len() / 2);
//
//         Some(match (mul_exprs(left), mul_exprs(right)) {
//             (Some(l), Some(r)) => l * r,
//             (Some(l), None) => l,
//             (None, Some(r)) => r,
//             _ => unreachable!(),
//         })
//     }
// }
