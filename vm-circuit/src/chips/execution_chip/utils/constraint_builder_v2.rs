use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_v2::Step;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder::ConditionalLookup;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::utils::StoredExpression;
use crate::utils::cell_manager::{Cell, CellType};
use crate::utils::challenges::Challenges;
use crate::utils::rlc::rlc;
use gadgets::util::Expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use std::collections::HashMap;
use types::Field;

// Max degree allowed in all expressions passing through the ConstraintBuilder.
// It aims to cap `extended_k` to 2, which allows constraint degree to 2^2+1,
// but each ExecutionGadget has implicit selector degree 3, so here it only
// allows 2^2+1-3 = 2.
const MAX_DEGREE: usize = 5;
const IMPLICIT_DEGREE: usize = 3;

pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    To(T),
}

impl<F> Default for Transition<F> {
    fn default() -> Self {
        Self::Same
    }
}

/// (state_name, transition)
pub(crate) type StateTransition<F> = (&'static str, Transition<F>);

/// Internal type to select the location where the constraints are enabled
#[derive(Debug, PartialEq, Copy, Clone)]
enum ConstraintLocation {
    FirstRow,
    LastRow,
    NotFirstRow,
    NotLastRow,
}

/// Collection of constraints grouped by which selectors will enable them
#[derive(Default)]
pub(crate) struct Constraints<F> {
    /// Enabled when cur row is the first row of the opcode
    pub(crate) first_row: Vec<(String, Expression<F>)>,
    /// Enabled when cur row is the last row of the opcode
    pub(crate) last_row: Vec<(String, Expression<F>)>,
    /// Enabled when cur row is not the first row of the opcode
    pub(crate) not_first_row: Vec<(String, Expression<F>)>,
    /// Enabled when cur row is not the last row of the opcode
    pub(crate) not_last_row: Vec<(String, Expression<F>)>,
}

pub(crate) struct ConstraintBuilderV2<'a, F: Field> {
    meta: &'a mut ConstraintSystem<F>,
    challenges: &'a Challenges<Expression<F>>,

    opcode: Opcode,
    pub(crate) curr: Step<F>,
    pub(crate) next: Step<F>,
    // constraints: Vec<(String, ConditionalExpression<F>)>,
    constraints: Constraints<F>,
    constraints_location: Option<ConstraintLocation>,
    conditions: Vec<Expression<F>>,
    // FIXME
    lookups: Vec<(&'static str, ConditionalLookup<F>)>,

    stored_expressions: Vec<StoredExpression<F>>,
    in_next_step: bool,
}

impl<'a, F: Field> ConstrainBuilderCommon<F> for ConstraintBuilderV2<'a, F> {
    fn add_constraint(&mut self, name: String, constraint: Expression<F>) {
        // let constraint = self.split_expression(
        //     name.as_str(),
        //     constraint * self.condition_expr(),
        //     MAX_DEGREE - IMPLICIT_DEGREE, // FIXME: check on the degree
        // );

        //self.validate_degree(constraint.degree(), name.as_str());

        self.push_constraint(name, constraint);
    }
}

impl<'a, F: Field> ConstraintBuilderV2<'a, F> {
    pub(crate) fn new(
        meta: &'a mut ConstraintSystem<F>,
        challenges: &'a Challenges<Expression<F>>,
        curr: Step<F>,
        next: Step<F>,
        opcode: Opcode,
    ) -> Self {
        Self {
            meta,
            challenges,
            opcode,
            curr,
            next,
            constraints: Default::default(),
            constraints_location: None,
            lookups: Vec::new(),
            stored_expressions: Vec::new(),
            in_next_step: false,
            conditions: Vec::new(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (
        Constraints<F>,
        Vec<(&'static str, ConditionalLookup<F>)>,
        Vec<StoredExpression<F>>,
        &'a mut ConstraintSystem<F>,
    ) {
        debug_assert_eq!(self.conditions.len(), 0);
        let op_sel = self.curr.execution_state_selector([self.opcode]);
        let mul_exec_state_sel = |c: Vec<(String, Expression<F>)>| {
            c.into_iter()
                .map(|(name, constraint)| (name, op_sel.clone() * constraint))
                .collect()
        };
        (
            Constraints {
                first_row: mul_exec_state_sel(self.constraints.first_row),
                not_first_row: mul_exec_state_sel(self.constraints.not_first_row),
                last_row: mul_exec_state_sel(self.constraints.last_row),
                not_last_row: mul_exec_state_sel(self.constraints.not_last_row),
            },
            self.lookups
                .into_iter()
                .map(|(name, mut lookup)| {
                    lookup.add_conditions(vec![op_sel.clone()]);
                    (name, lookup)
                })
                .collect(),
            self.stored_expressions,
            self.meta,
        )
    }

    pub(crate) fn query_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase1)
    }

    pub(crate) fn query_cell_phase2(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase2)
    }

    pub(crate) fn query_copy_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePermutation)
    }

    pub(crate) fn query_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1).first().unwrap().clone()
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        if self.in_next_step {
            &mut self.next
        } else {
            &mut self.curr
        }
        .cell_manager
        .query_cells(self.meta, cell_type, count)
    }

    /// require next row's execution state to be the specified `execution_state`
    pub(crate) fn require_next_state(&mut self, execution_state: Opcode) {
        let next_state = self.next.execution_state_selector([execution_state]);
        self.require_equal(
            "Constrain next execution state",
            1u64.expr(),
            next_state.expr(),
        );
    }

    pub(crate) fn require_state_transition(
        &mut self,
        step_state_transition: Vec<StateTransition<Expression<F>>>,
    ) {
        macro_rules! constrain {
            ($transition:ident, $name:tt) => {
                if let Some(c) = $transition.remove(stringify!($name)) {
                    match c {
                        Transition::Same => self.require_equal(
                            concat!("State transition (same) constraint of ", stringify!($name)),
                            self.next.state.$name.expr(),
                            self.curr.state.$name.expr(),
                        ),
                        Transition::Delta(delta) => self.require_equal(
                            concat!("State transition (delta) constraint of ", stringify!($name)),
                            self.next.state.$name.expr(),
                            self.curr.state.$name.expr() + delta,
                        ),
                        Transition::To(to) => self.require_equal(
                            concat!("State transition (to) constraint of ", stringify!($name)),
                            self.next.state.$name.expr(),
                            to,
                        ),
                    }
                }
            };
        }
        let mut step_state_transition = step_state_transition
            .into_iter()
            .collect::<HashMap<&'static str, _>>();
        constrain!(step_state_transition, frame_index);
        constrain!(step_state_transition, module_index);
        constrain!(step_state_transition, function_index);
        constrain!(step_state_transition, pc);
        constrain!(step_state_transition, sp);
        constrain!(step_state_transition, opcode);
        constrain!(step_state_transition, aux0);
        constrain!(step_state_transition, aux1);
        constrain!(step_state_transition, step_counter);
        // TODO: add other state variable
    }

    // Lookups

    pub(crate) fn add_lookup(&mut self, name: &str, lookup: Lookup<F>) {
        debug_assert!(
            self.constraints_location.is_some(),
            "lookup do not support conditional without constraint location"
        );
        let lookup = match self.condition_expr_opt() {
            Some(condition) => lookup.conditional(condition),
            None => lookup,
        };
        let lookup_rlc_expr = rlc::expr(&lookup.input_exprs(), self.challenges.lookup_input());
        // FIXME: check the compression.
        // let compressed_expr = self.split_expression(
        //     "Lookup compression",
        //     lookup_rlc_expr,
        //     MAX_DEGREE - IMPLICIT_DEGREE,
        // );

        self.store_expression(name, lookup_rlc_expr, CellType::Lookup(lookup.table()));
    }

    pub(crate) fn store_expression(
        &mut self,
        name: &str,
        expr: Expression<F>,
        cell_type: CellType,
    ) -> Expression<F> {
        // Check if we already stored the expression somewhere
        let stored_expression = self.find_stored_expression(&expr, cell_type);

        match stored_expression {
            Some(stored_expression) => {
                debug_assert!(
                    !matches!(cell_type, CellType::Lookup(_)),
                    "The same lookup is done multiple times",
                );
                stored_expression.cell.expr()
            }
            None => {
                // Even if we're building expressions for the next step,
                // these intermediate values need to be stored in the current step.
                let in_next_step = self.in_next_step;
                self.in_next_step = false;
                let cell = self.query_cell_with_type(cell_type);
                self.in_next_step = in_next_step;

                // Require the stored value to equal the value of the expression
                let name = format!("{} (stored expression)", name);
                self.push_constraint(name.clone(), cell.expr() - expr.clone());

                self.stored_expressions.push(StoredExpression {
                    name,
                    cell: cell.clone(),
                    cell_type,
                    expr_id: expr.identifier(),
                    expr,
                });
                cell.expr()
            }
        }
    }

    pub(crate) fn find_stored_expression(
        &self,
        expr: &Expression<F>,
        cell_type: CellType,
    ) -> Option<&StoredExpression<F>> {
        let expr_id = expr.identifier();
        self.stored_expressions
            .iter()
            .find(|&e| e.cell_type == cell_type && e.expr_id == expr_id)
    }

    fn split_expression(
        &mut self,
        name: &str,
        expr: Expression<F>,
        max_degree: usize,
    ) -> Expression<F> {
        if expr.degree() > max_degree {
            match expr {
                Expression::Negated(poly) => {
                    Expression::Negated(Box::new(self.split_expression(name, *poly, max_degree)))
                }
                Expression::Scaled(poly, v) => {
                    Expression::Scaled(Box::new(self.split_expression(name, *poly, max_degree)), v)
                }
                Expression::Sum(a, b) => {
                    let a = self.split_expression(name, *a, max_degree);
                    let b = self.split_expression(name, *b, max_degree);
                    a + b
                }
                Expression::Product(a, b) => {
                    let (mut a, mut b) = (*a, *b);
                    while a.degree() + b.degree() > max_degree {
                        let mut split = |expr: Expression<F>| {
                            if expr.degree() > max_degree {
                                self.split_expression(name, expr, max_degree)
                            } else {
                                let cell_type = CellType::storage_for_expr(&expr);
                                self.store_expression(name, expr, cell_type)
                            }
                        };
                        if a.degree() >= b.degree() {
                            a = split(a);
                        } else {
                            b = split(b);
                        }
                    }
                    a * b
                }
                _ => expr.clone(),
            }
        } else {
            expr.clone()
        }
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

    fn constraint_at_location<R>(
        &mut self,
        location: ConstraintLocation,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.constraints_location.is_none(),
            "ConstraintLocation can't be combined"
        );
        self.constraints_location = Some(location);
        let ret = constraint(self);
        self.constraints_location = None;
        ret
    }
    /// register constraints to be applied `first_row` selector
    pub(crate) fn first_row<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::FirstRow, constraint)
    }
    /// register constraints to be applied `not_first_row` selector
    pub(crate) fn not_first_row<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::NotFirstRow, constraint)
    }

    /// register constraints to be applied on step other than last row
    pub(crate) fn not_last_row<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::NotLastRow, constraint)
    }
    /// register constraints to be applied on last row
    pub(crate) fn last_row<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::LastRow, constraint)
    }

    /// register constraints to be applied on respective selector later
    fn push_constraint(&mut self, name: String, constraint: Expression<F>) {
        debug_assert!(
            self.constraints_location.is_some(),
            "ConstraintLocation can't be combined"
        );
        match self.constraints_location.unwrap() {
            ConstraintLocation::FirstRow => self.constraints.first_row.push((name, constraint)),
            ConstraintLocation::NotFirstRow => {
                self.constraints.not_first_row.push((name, constraint))
            }
            ConstraintLocation::LastRow => self.constraints.last_row.push((name, constraint)),
            ConstraintLocation::NotLastRow => {
                self.constraints.not_last_row.push((name, constraint))
            }
        }
    }

    fn condition_expr(&self) -> Expression<F> {
        match self.condition_expr_opt() {
            Some(condition) => condition,
            None => 1u64.expr(),
        }
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

    pub(crate) fn validate_degree(&self, degree: usize, name: &str) {
        // We need to subtract IMPLICIT_DEGREE from MAX_DEGREE because all expressions
        // will be multiplied by state selector and q_step/q_step_first
        // selector.
        debug_assert!(
            degree <= MAX_DEGREE - IMPLICIT_DEGREE,
            "Expression {} degree too high: {} > {}",
            name,
            degree,
            MAX_DEGREE - IMPLICIT_DEGREE,
        );
    }
}

pub fn mul_exprs<F: Field>(iter: impl AsRef<[Expression<F>]>) -> Option<Expression<F>> {
    let mut iter = iter.as_ref().iter();
    let first = match iter.next() {
        Some(e) => e,
        None => return None,
    };
    Some(iter.fold(first.clone(), |acc, e| acc * e.clone()))
}

// pub fn mul_exprs<F: Field>(iter: impl AsRef<[Expression<F>]>) -> Option<Expression<F>> {
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
