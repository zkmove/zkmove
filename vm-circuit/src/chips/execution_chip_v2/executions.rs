pub mod borrow_loc;
pub mod br_bool;
pub mod ld;
pub mod pack;

pub use borrow_loc::*;
pub use br_bool::*;
pub use ld::*;
pub use pack::*;

use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::utilities::Expr;
use halo2_proofs::plonk::Expression;
use strum_macros::EnumIter;
use types::Field;

#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ExecutionState {
    BrTrue,
    BrFalse,
    Stop,
    Nop,
}

#[derive(Clone, Debug)]
pub(crate) struct ValueHeader<F> {
    len: Expression<F>,
    flen: Expression<F>,
}

impl<F: Field> ValueHeader<F> {
    fn new(cb: &mut ConstraintBuilderV2<F>) -> Self {
        Self {
            len: cb.query_cell().expr(),
            flen: cb.query_cell().expr(),
        }
    }
    fn pair(len: Expression<F>, flen: Expression<F>) -> Self {
        Self { len, flen }
    }
    // header for any reference value
    pub fn default() -> Self {
        Self::pair(3u64.expr(), 4u64.expr())
    }
}

impl<F: Field> Expr<F> for ValueHeader<F> {
    fn expr(&self) -> Expression<F> {
        self.flen.clone() + self.len.clone() * 2u64.pow(16).expr()
    }
}
