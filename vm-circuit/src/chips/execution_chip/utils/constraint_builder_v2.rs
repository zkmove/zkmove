use crate::chips::execution_chip::lookup_tables::Lookup;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_v2::Step;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder::ConditionalLookup;
use crate::chips::execution_chip::utils::CellType;
use crate::chips::utilities::{Cell, Expr};
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use types::Field;

// Max degree allowed in all expressions passing through the ConstraintBuilder.
// It aims to cap `extended_k` to 2, which allows constraint degree to 2^2+1,
// but each ExecutionGadget has implicit selector degree 3, so here it only
// allows 2^2+1-3 = 2.
const MAX_DEGREE: usize = 5;
const IMPLICIT_DEGREE: usize = 3;

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
    opcode: Opcode,
    pub(crate) curr: Step<F>,
    pub(crate) next: Step<F>,
    // constraints: Vec<(String, ConditionalExpression<F>)>,
    constraints: Constraints<F>,
    constraints_location: Option<ConstraintLocation>,
    conditions: Vec<Expression<F>>,
    // FIXME
    lookups: Vec<(&'static str, ConditionalLookup<F>)>,
    in_next_step: bool,
}

impl<'a, F: Field> ConstrainBuilderCommon<F> for ConstraintBuilderV2<'a, F> {
    fn add_constraint(&mut self, name: String, constraint: Expression<F>) {
        // FIXME
        // let constraint = self.split_expression(
        //     name,
        //     constraint * self.condition_expr(),
        //     MAX_DEGREE - IMPLICIT_DEGREE,
        // );
        //
        // self.validate_degree(constraint.degree(), name);
        self.push_constraint(name, constraint);
    }
}

impl<'a, F: Field> ConstraintBuilderV2<'a, F> {
    pub(crate) fn new(
        meta: &'a mut ConstraintSystem<F>,
        curr: Step<F>,
        next: Step<F>,
        opcode: Opcode,
    ) -> Self {
        Self {
            meta,
            opcode,
            curr,
            next,
            constraints: Default::default(),
            constraints_location: None,
            lookups: Vec::new(),
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
            self.meta,
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
