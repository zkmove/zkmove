use crate::chips::utils::Expr;
use halo2_proofs::plonk::Expression;
use types::Field;
pub(crate) trait ConstrainBuilderCommon<F: Field> {
    fn add_constraint(&mut self, name: String, constraint: Expression<F>);

    fn require_zero(&mut self, name: impl AsRef<str>, constraint: Expression<F>) {
        self.add_constraint(name.as_ref().to_string(), constraint);
    }

    // fn require_zero_word(&mut self, name: String, word: WordLoHi<Expression<F>>) {
    //     self.require_equal_word(name, word, WordLoHi::zero());
    // }

    // fn require_equal_word(
    //     &mut self,
    //     name: String,
    //     lhs: WordLoHi<Expression<F>>,
    //     rhs: WordLoHi<Expression<F>>,
    // ) {
    //     let (lhs_lo, lhs_hi) = lhs.to_lo_hi();
    //     let (rhs_lo, rhs_hi) = rhs.to_lo_hi();
    //     self.add_constraint(name, lhs_lo - rhs_lo);
    //     self.add_constraint(name, lhs_hi - rhs_hi);
    // }

    fn require_equal(&mut self, name: impl AsRef<str>, lhs: Expression<F>, rhs: Expression<F>) {
        self.add_constraint(name.as_ref().to_string(), lhs - rhs);
    }

    fn require_boolean(&mut self, name: impl AsRef<str>, value: Expression<F>) {
        self.add_constraint(
            name.as_ref().to_string(),
            value.clone() * (1u64.expr() - value),
        );
    }

    fn require_true(&mut self, name: impl AsRef<str>, value: Expression<F>) {
        self.require_equal(name, value, 1u64.expr());
    }

    fn require_in_set(
        &mut self,
        name: impl AsRef<str>,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name.as_ref().to_string(),
            set.iter().fold(1u64.expr(), |acc, item| {
                acc * (value.clone() - item.clone())
            }),
        );
    }
    /// Under active development
    #[allow(dead_code)]
    fn add_constraints(&mut self, constraints: Vec<(String, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }
}

#[derive(Default)]
pub struct BaseConstraintBuilder<F> {
    pub constraints: Vec<(String, Expression<F>)>,
    pub max_degree: usize,
    pub condition: Option<Expression<F>>,
}

impl<F: Field> ConstrainBuilderCommon<F> for BaseConstraintBuilder<F> {
    fn add_constraint(&mut self, name: String, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree(), &name);
        self.constraints.push((name, constraint));
    }
}
impl<F: Field> BaseConstraintBuilder<F> {
    pub(crate) fn new(max_degree: usize) -> Self {
        BaseConstraintBuilder {
            constraints: Vec::new(),
            max_degree,
            condition: None,
        }
    }

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn validate_degree(&self, degree: usize, name: &str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }

    pub(crate) fn gate(&self, selector: Expression<F>) -> Vec<(String, Expression<F>)> {
        self.constraints
            .clone()
            .into_iter()
            .map(|(name, constraint)| (name, selector.clone() * constraint))
            .filter(|(name, constraint)| {
                self.validate_degree(constraint.degree(), name);
                true
            })
            .collect()
    }
}
