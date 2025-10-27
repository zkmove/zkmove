use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::lookup_table::{FixedTableTag, Lookup, Table};
use crate::execution_circuit::step::{Step, StepState};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cell_manager::{Cell, CellManagerColumns, CellType};
use circuit_tool::challenges::Challenges;
use circuit_tool::rlc;
use circuit_tool::stored_expression::StoredExpression;
use field_exts::Field;
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use std::collections::HashMap;
use util::Expr;

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
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub(crate) enum ConstraintLocation {
    FirstRow,
    LastRow,
    NotFirstRow,
    NotLastRow,
}

pub(crate) type Located<T> = HashMap<Option<ConstraintLocation>, Vec<T>>;

/// Collection of constraints grouped by which selectors will enable them
pub(crate) type Constraints<F> = Located<(String, Expression<F>)>;

/// Collection of lookups grouped by which selectors will enable them
pub(crate) type Lookups<F> = Located<(String, Lookup<F>)>;

/// Collection of stored expressions grouped by which selectors will enable them
pub(crate) type StoredExpressions<F> = Located<StoredExpression<F>>;

pub(crate) struct VmConstraintBuilder<'a, F: Field> {
    meta: &'a mut ConstraintSystem<F>,
    pub(crate) columns: &'a mut CellManagerColumns,
    challenges: &'a Challenges<Expression<F>>,

    execution_state: Option<ExecutionState>,
    pub(crate) curr: Step<F>,

    conditions: Vec<Expression<F>>,
    constraints_location: Option<ConstraintLocation>,

    constraints: Constraints<F>,
    lookups: Lookups<F>,
    stored_expressions: StoredExpressions<F>,

    in_next_step: bool,
}

impl<F: Field> ConstraintBuilder<F> for VmConstraintBuilder<'_, F> {
    fn add_constraint(&mut self, name: String, constraint: Expression<F>) {
        let constraint = constraint * self.condition_expr();
        // let constraint = self.split_expression(
        //     name.as_str(),
        //     constraint,
        //     MAX_DEGREE - IMPLICIT_DEGREE, // FIXME: check on the degree
        // );

        // self.validate_degree(constraint.degree(), name.as_str());

        self.push_constraint(name, constraint);
    }

    fn query_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase1)
    }

    fn query_bool(&mut self) -> Cell<F> {
        let cell = self.query_cell();
        self.require_boolean("Constrain cell to be a bool".to_string(), cell.expr());
        cell
    }

    fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_u8_vec(N).try_into().unwrap()
    }
}

impl<'a, F: Field> VmConstraintBuilder<'a, F> {
    pub(crate) fn new(
        meta: &'a mut ConstraintSystem<F>,
        columns: &'a mut CellManagerColumns,
        challenges: &'a Challenges<Expression<F>>,
        curr: Step<F>,
        exec_state: Option<ExecutionState>,
    ) -> Self {
        Self {
            meta,
            columns,
            challenges,
            execution_state: exec_state,
            curr,

            constraints_location: None,

            in_next_step: false,
            conditions: Vec::new(),
            constraints: Default::default(),
            lookups: Default::default(),
            stored_expressions: Default::default(),
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (
        Step<F>,
        Constraints<F>,
        Lookups<F>,
        StoredExpressions<F>,
        &'a mut ConstraintSystem<F>,
        &'a mut CellManagerColumns,
    ) {
        debug_assert_eq!(self.conditions.len(), 0);
        // let op_sel = match self.execution_state {
        //     Some(s) => self.curr.execution_state_selector([s]),
        //     None => 1u64.expr(),
        // };
        // let mul_exec_state_sel = |c: Vec<(String, Expression<F>)>| {
        //     c.into_iter()
        //         .map(|(name, constraint)| (name, op_sel.clone() * constraint))
        //         .collect()
        // };

        (
            self.curr,
            self.constraints,
            self.lookups,
            self.stored_expressions,
            self.meta,
            self.columns,
        )
    }

    pub fn step_state_at_offset(&mut self, offset: isize) -> StepState<F> {
        Step::new(self.meta, self.columns, offset, self.challenges).state
    }

    pub(crate) fn query_bools<const N: usize>(&mut self) -> [Cell<F>; N] {
        (0..N)
            .map(|_| self.query_bool())
            .collect::<Vec<_>>()
            .try_into()
            .expect("Failed to query cells")
    }
    pub(crate) fn query_byte(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::Lookup(Table::U8))
    }
    #[cfg(feature = "table-u16")]
    pub(crate) fn query_u16(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::Lookup(Table::U16))
    }
    // pub(crate) fn query_nibble(&mut self) -> Cell<F> {
    //     self.query_cell_with_type(CellType::Lookup(Table::Nibble))
    // }
    pub(crate) fn query_u8_vec(&mut self, count: usize) -> Vec<Cell<F>> {
        self.query_cells_inner(CellType::Lookup(Table::U8), count)
    }

    pub(crate) fn query_cell_phase0(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase0)
    }
    pub(crate) fn query_cell_enable_equality(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase1EnableEquality)
    }
    // pub(crate) fn query_copy_cell(&mut self) -> Cell<F> {
    //     self.query_cell_with_type(CellType::StoragePermutation)
    // }

    pub(crate) fn query_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells_inner(cell_type, 1)
            .first()
            .unwrap()
            .clone()
    }

    pub(crate) fn query_cells<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_cells_inner(CellType::StoragePhase1, N)
            .try_into()
            .unwrap()
    }

    fn query_cells_inner(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        assert!(!self.in_next_step, "can only query cells in current step");
        self.curr
            .cell_manager
            .query_cells(self.meta, self.columns, cell_type, count)
    }
    /// This function needs to be used with extra precaution. You need to make
    /// sure the layout is the same as the gadget for `next_step_state`.
    /// `query_cell` will return cells in the next step in the `constraint`
    /// function.
    pub(crate) fn constrain_next_step<R>(
        &mut self,
        next_step_state: ExecutionState,
        condition: Option<Expression<F>>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        assert!(!self.in_next_step, "Already in the next step");
        self.in_next_step = true;
        let ret = match condition {
            None => {
                self.require_next_state(next_step_state);
                constraint(self)
            }
            Some(cond) => self.condition(cond, |cb| {
                cb.require_next_state(next_step_state);
                constraint(cb)
            }),
        };
        self.in_next_step = false;
        ret
    }
    #[cfg(not(feature = "test-circuits"))]
    pub(crate) fn cell_at_offset(&mut self, cell: &Cell<F>, offset: i32) -> Cell<F> {
        cell.at_offset(offset)
    }
    #[cfg(feature = "test-circuits")]
    pub(crate) fn cell_at_offset(&mut self, cell: &Cell<F>, offset: i32) -> Cell<F> {
        cell.at_offset(self.meta, offset)
    }

    pub(crate) fn cells_at_offset<const N: usize>(
        &mut self,
        cells: [Cell<F>; N],
        offset: i32,
    ) -> [Cell<F>; N] {
        cells.map(|c| self.cell_at_offset(&c, offset))
    }

    /// require next row's execution state to be the specified `execution_state`
    pub(crate) fn require_next_state(&mut self, execution_state: ExecutionState) {
        let step = self.step_state_at_offset(1);
        let next_state = step.execution_state_selector([execution_state]);
        self.require_equal(
            "Constrain next execution state".to_string(),
            1u64.expr(),
            next_state.expr(),
        );
    }
    pub(crate) fn require_next_states(&mut self, execution_states: Vec<ExecutionState>) {
        let step = self.step_state_at_offset(1);
        let next_state = step.execution_state_selector(execution_states);
        self.require_equal(
            "Constrain next execution state".to_string(),
            1u64.expr(),
            next_state.expr(),
        );
    }
    pub(crate) fn require_prev_state(&mut self, execution_state: ExecutionState) {
        let prev = self.step_state_at_offset(-1);
        let prev_state = prev.execution_state_selector([execution_state]);
        self.require_equal(
            "Constrain prev execution state".to_string(),
            1u64.expr(),
            prev_state.expr(),
        );
    }
    pub(crate) fn require_prev_states(&mut self, execution_states: Vec<ExecutionState>) {
        let prev = self.step_state_at_offset(-1);
        let prev_state = prev.execution_state_selector(execution_states);
        self.require_equal(
            "Constrain prev execution state".to_string(),
            1u64.expr(),
            prev_state.expr(),
        );
    }

    pub(crate) fn require_cell_transition(
        &mut self,
        cell: Cell<F>,
        transition: Transition<Expression<F>>,
    ) {
        let cell_next = self.cell_at_offset(&cell, 1);
        match transition {
            Transition::Same => self.require_equal(
                "cell transition (same) constraint".to_string(),
                cell_next.expr(),
                cell.expr(),
            ),
            Transition::Delta(delta) => self.require_equal(
                "Cell transition (delta) constraint".to_string(),
                cell_next.expr(),
                cell.expr() + delta,
            ),
            Transition::To(to) => self.require_equal(
                "Cell transition (to) constraint".to_string(),
                cell_next.expr(),
                to,
            ),
        }
    }

    pub(crate) fn require_state_transition(
        &mut self,
        step_state_transition: Vec<StateTransition<Expression<F>>>,
    ) {
        let step_state_next = self.step_state_at_offset(1);
        macro_rules! constrain {
            ($transition:ident, $name:tt) => {
                if let Some(c) = $transition.remove(stringify!($name)) {
                    match c {
                        Transition::Same => self.require_equal(
                            concat!("State transition (same) constraint of ", stringify!($name))
                                .to_string(),
                            step_state_next.$name.expr(),
                            self.curr.state.$name.expr(),
                        ),
                        Transition::Delta(delta) => self.require_equal(
                            concat!("State transition (delta) constraint of ", stringify!($name))
                                .to_string(),
                            step_state_next.$name.expr(),
                            self.curr.state.$name.expr() + delta,
                        ),
                        Transition::To(to) => self.require_equal(
                            concat!("State transition (to) constraint of ", stringify!($name))
                                .to_string(),
                            step_state_next.$name.expr(),
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
        constrain!(step_state_transition, operand0);
        constrain!(step_state_transition, operand1);
        constrain!(step_state_transition, step_counter);
        // TODO: add other state variable
    }

    pub(crate) fn require_no_stack_push(&mut self) {
        self.require_zero(
            "none stack push".to_string(),
            self.curr.state.stack_push_version.expr(),
        );
    }
    pub(crate) fn require_no_stack_pop(&mut self) {
        self.require_zero(
            "none stack pop".to_string(),
            self.curr.state.stack_pop_version.expr(),
        );
    }
    pub(crate) fn require_no_local_op(&mut self) {
        self.require_zero(
            "none local op".to_string(),
            self.curr.state.local_read_version.expr(),
        );
        self.require_zero(
            "none local op".to_string(),
            self.curr.state.local_write_version.expr(),
        );
    }
    pub(crate) fn require_read_invalid_value(&mut self) {
        self.require_true(
            "read value is invalid".to_string(),
            self.curr.state.local_read_value_invalid.expr(),
        );
    }
    pub(crate) fn require_write_invalid_value(&mut self) {
        self.require_true(
            "write value is invalid".to_string(),
            self.curr.state.local_write_value_invalid.expr(),
        );
    }

    pub(crate) fn rlc_with_randomness(
        &self,
        expressions: &[Expression<F>],
        randomness: Expression<F>,
    ) -> Expression<F> {
        rlc::expr(expressions, randomness)
    }
    pub(crate) fn row_randomness(&self) -> Expression<F> {
        self.challenges.row_keccak_input()
    }
    pub(crate) fn column_randomness(&self) -> Expression<F> {
        self.challenges.column_keccak_input()
    }
    // Lookups
    pub(crate) fn range_lookup(&mut self, lookup_name: String, value: Expression<F>, range: u64) {
        let (name, tag) = match range {
            16 => ("Range16", FixedTableTag::Range16),
            32 => ("Range32", FixedTableTag::Range32),
            64 => ("Range64", FixedTableTag::Range64),
            128 => ("Range128", FixedTableTag::Range128),
            256 => ("Range256", FixedTableTag::Range256),
            1024 => ("Range1024", FixedTableTag::Range1024),
            _ => unimplemented!(),
        };
        self.add_lookup_directly(
            format!("{}-{}", name, lookup_name),
            Lookup::Fixed {
                tag: tag.expr(),
                values: [value, 0.expr(), 0.expr()],
            },
        );
    }
    pub(crate) fn add_lookup_directly(&mut self, name: String, lookup: Lookup<F>) {
        let lookup = match self.condition_expr_opt() {
            Some(condition) => lookup.conditional(condition),
            None => lookup,
        };
        self.lookups
            .entry(self.constraints_location)
            .or_default()
            .push((name, lookup))
    }

    pub(crate) fn add_lookup(&mut self, name: &str, lookup: Lookup<F>) {
        // debug_assert!(
        //     self.constraints_location.is_some(),
        //     "lookup do not support conditional without constraint location"
        // );
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
        let stored_expression =
            self.find_stored_expression(&expr, cell_type, self.constraints_location);

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

                let stored_expression = StoredExpression {
                    name,
                    cell: cell.clone(),
                    cell_type,
                    expr_id: expr.identifier(),
                    expr,
                };
                self.stored_expressions
                    .entry(self.constraints_location)
                    .or_default()
                    .push(stored_expression);
                cell.expr()
            }
        }
    }

    pub(crate) fn find_stored_expression(
        &self,
        expr: &Expression<F>,
        cell_type: CellType,
        constraint_location: Option<ConstraintLocation>,
    ) -> Option<&StoredExpression<F>> {
        let expr_id = expr.identifier();
        self.stored_expressions
            .get(&constraint_location)
            .and_then(|es| {
                es.iter()
                    .find(|&e| e.cell_type == cell_type && e.expr_id == expr_id)
            })
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
                                let cell_type = CellType::storage_for_expr(self.meta, &expr);
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
        // debug_assert!(
        //     self.constraints_location.is_some(),
        //     "ConstraintLocation can't be combined"
        // );
        self.constraints
            .entry(self.constraints_location)
            .or_default()
            .push((name, constraint));
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
        let first = iter.next()?;
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
