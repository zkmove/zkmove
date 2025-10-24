use field_exts::Field;
use halo2_proofs::plonk::Expression;
use util::pow_of_two_expr;
use util::Expr;

#[derive(Clone, Debug)]
pub struct Integer<F> {
    pub lo: Expression<F>,
    pub hi: Expression<F>,
}

impl<F: Field> Integer<F> {
    pub fn new(lo: Expression<F>, hi: Expression<F>) -> Self {
        Self { lo, hi }
    }
    pub fn lo(&self) -> Expression<F> {
        self.lo.clone()
    }
    pub fn hi(&self) -> Expression<F> {
        self.hi.clone()
    }
    pub fn exprs(&self) -> (Expression<F>, Expression<F>) {
        (self.lo.clone(), self.hi.clone())
    }
    pub fn expr(&self) -> Expression<F> {
        self.lo.clone() + self.hi.clone() * pow_of_two_expr(128)
    }
    pub fn select(
        selector: Expression<F>,
        when_true: Integer<F>,
        when_false: Integer<F>,
    ) -> Integer<F> {
        let (true_lo, true_hi) = when_true.exprs();
        let (false_lo, false_hi) = when_false.exprs();
        Integer::new(
            selector.clone() * true_lo + (1u64.expr() - selector.clone()) * false_lo,
            selector.clone() * true_hi + (1u64.expr() - selector.clone()) * false_hi,
        )
    }
}
