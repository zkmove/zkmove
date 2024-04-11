use crate::chips::execution_chip::utils::base_constraint_builder::{
    BaseConstraintBuilder, ConstrainBuilderCommon,
};
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::execution_chip::utils::pow_of_two;
use crate::chips::utilities::{from_bytes, Cell, Expr};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use types::Field;

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER` to prevent overflow:
/// values are stored in a single field element and two of these are added
/// together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**N_BYTES` and `lt` is boolean, `lt` can only
/// be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct LtGadget<F, const N_BYTES: usize> {
    lt: Cell<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: Vec<Cell<F>>, /* The byte values of `diff`.
                  * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                  * `lhs - rhs + range` otherwise. */
    range: F, // The range of the inputs, `256**N_BYTES`
}

impl<F: Field, const N_BYTES: usize> LtGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let mut bcb = BaseConstraintBuilder::default();
        let lt = cb.alloc_cell();
        let diff = cb.alloc_n_cells(N_BYTES);
        let range = pow_of_two(N_BYTES * 8);

        // lt must be bool
        bcb.require_boolean("Constrain lt to be a bool", lt.expr());

        // The equation we require to hold: `lhs - rhs + lt * range == diff`.
        bcb.require_equal(
            "lhs - rhs + lt ⋅ range == diff",
            lhs - rhs + (lt.expr() * range),
            from_bytes::expr(&diff),
        );
        cb.add_constraints(bcb.constraints);

        Self { lt, diff, range }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.lt.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, Vec<u8>), Error> {
        // Set `lt`
        let lt = lhs < rhs;
        self.lt
            .assign(region, offset, Some(if lt { F::ONE } else { F::ZERO }))?;

        // Set the bytes of diff
        let diff = (lhs - rhs) + (if lt { self.range } else { F::ZERO });
        let binding = diff.to_repr();
        let diff_bytes = binding.as_ref();
        for (idx, diff) in self.diff.iter().enumerate() {
            diff.assign(region, offset, Some(F::from(diff_bytes[idx] as u64)))?;
        }

        Ok((if lt { F::ONE } else { F::ZERO }, diff_bytes.to_vec()))
    }

    #[allow(dead_code)]
    pub(crate) fn diff_bytes(&self) -> Vec<Cell<F>> {
        self.diff.to_vec()
    }

    // pub(crate) fn assign_value(
    //     &self,
    //     region: &mut Region<'_, F>,
    //     offset: usize,
    //     lhs: Value,
    //     rhs: Value,
    // ) -> Result<Value<(F, Vec<u8>)>, Error> {
    //     transpose_val_ret(
    //         lhs.zip(rhs)
    //             .map(|(lhs, rhs)| self.assign(region, offset, lhs, rhs)),
    //     )
    // }
}
