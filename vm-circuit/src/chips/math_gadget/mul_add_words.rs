use crate::chips::execution_chip::utils::base_constraint_builder::{
    BaseConstraintBuilder, ConstrainBuilderCommon,
};
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::execution_chip::utils::{pow_of_two_expr, split_u256, split_u256_limb64};
use crate::chips::utilities::{from_bytes, Cell, Expr};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_core_types::u256::U256;
use types::Field;

pub const MAX_RADIX_BYTES: usize = 9;

pub struct MulAddWordsOp<F: Field> {
    pub a_hi: Expression<F>,
    pub a_lo: Expression<F>,
    pub b_hi: Expression<F>,
    pub b_lo: Expression<F>,
    pub c_hi: Expression<F>,
    pub c_lo: Expression<F>,
    pub d_hi: Expression<F>,
    pub d_lo: Expression<F>,
}

/// the algorithm is adapted from PSE's implementation.
///
/// Construct the gadget that checks a * b + c == d (modulo 2**256),
/// where a, b, c, d are 256-bit words. This can be used by opcode MUL, DIV,
/// and MOD. For opcode MUL, set c to 0. For opcode DIV and MOD, treat c as
/// residue and d as dividend.
///
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3
///   t0 = a0 * b0, contribute to 0 ~ 128 bit
///   t1 = a0 * b1 + a1 * b0, contribute to 64 ~ 193 bit (include the carry)
///   t2 = a0 * b2 + a2 * b0 + a1 * b1, contribute to above 128 bit
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, contribute to above 192 bit
///
/// so t0 ~ t3 include all contributions to the low 256-bit of product, with
/// a maximum 68-bit radix (the part higher than 256-bit), denoted as carry_hi
/// Similarly, we define carry_lo as the radix of contributions to the low
/// 128-bit of the product.
/// We can slightly relax the constraint of carry_lo/carry_hi to 72-bit and
/// allocate 9 bytes for them each
///
/// Finally we just prove:
///   t0 + t1 * 2^64 = <low 128 bit of product> + carry_lo * 2^128
///   t2 + t3 * 2^64 + carry_lo = <high 128 bit of product> + carry_hi * 2^128
///
/// Last, we sum the parts that are higher than 256-bit in the multiplication
/// into overflow
///   overflow = carry_hi + a1 * b3 + a2 * b2 + a3 * b1 + a2 * b3 + a3 * b2
///              + a3 * b3
/// In the cases of DIV and MOD, we need to constrain overflow == 0 outside the
/// MulAddWordsGadget.
#[derive(Clone, Debug)]
pub(crate) struct MulAddWordsGadget<F> {
    a_limbs: Vec<Cell<F>>,
    b_limbs: Vec<Cell<F>>,
    c_hi: Cell<F>,
    c_lo: Cell<F>,
    d_hi: Cell<F>,
    d_lo: Cell<F>,
    carry_lo: Vec<Cell<F>>,
    carry_hi: Vec<Cell<F>>,
    // overflow: Expression<F>,
}

#[derive(Clone, Debug)]
pub struct DoubleField<F: Field>(pub(crate) [Cell<F>; 2]);
#[derive(Clone, Debug)]
pub struct QuadField<F: Field>(pub(crate) [Cell<F>; 4]);

impl<F: Field> MulAddWordsGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let a_limbs = cb.alloc_n_cells(4);
        let b_limbs = cb.alloc_n_cells(4);
        let c_hi = cb.alloc_cell();
        let c_lo = cb.alloc_cell();
        let d_hi = cb.alloc_cell();
        let d_lo = cb.alloc_cell();
        let carry_lo = cb.alloc_n_cells(MAX_RADIX_BYTES);
        let carry_hi = cb.alloc_n_cells(MAX_RADIX_BYTES);

        Self {
            a_limbs,
            b_limbs,
            c_hi,
            c_lo,
            d_hi,
            d_lo,
            carry_lo,
            carry_hi,
            //overflow,
        }
    }

    pub(crate) fn configure(&self, cb: &mut ConstraintBuilder<F>, expr: MulAddWordsOp<F>) {
        let carry_lo_expr = from_bytes::expr(&self.carry_lo);
        let carry_hi_expr = from_bytes::expr(&self.carry_hi);

        let mut a_limbs = vec![];
        let mut b_limbs = vec![];
        for i in 0..4 {
            a_limbs.push(self.a_limbs.get(i).unwrap().expr());
            b_limbs.push(self.b_limbs.get(i).unwrap().expr());
        }
        let c_hi = self.c_hi.expression.clone();
        let c_lo = self.c_lo.expression.clone();
        let d_hi = self.d_hi.expression.clone();
        let d_lo = self.d_lo.expression.clone();

        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();

        let mut bcb = BaseConstraintBuilder::default();
        bcb.require_equal(
            "(a * b)_lo + c_lo == d_lo + carry_lo ⋅ 2^128",
            t0 + t1 * pow_of_two_expr(64) + c_lo.clone(),
            d_lo.clone() + carry_lo_expr.clone() * pow_of_two_expr(128),
        );
        bcb.require_equal(
            "(a * b)_hi + c_hi + carry_lo == d_hi + carry_hi ⋅ 2^128",
            t2 + t3 * pow_of_two_expr(64) + c_hi.clone() + carry_lo_expr,
            d_hi.clone() + carry_hi_expr * pow_of_two_expr(128),
        );

        // constrain on each cell equal to outer cells.
        let a_hi = a_limbs[3].clone() * pow_of_two_expr(64) + a_limbs[2].clone();
        let a_lo = a_limbs[1].clone() * pow_of_two_expr(64) + a_limbs[0].clone();
        cb.add_constraint("a_hi", a_hi - expr.a_hi);
        cb.add_constraint("a_lo", a_lo - expr.a_lo);
        let b_hi = b_limbs[3].clone() * pow_of_two_expr(64) + b_limbs[2].clone();
        let b_lo = b_limbs[1].clone() * pow_of_two_expr(64) + b_limbs[0].clone();
        cb.add_constraint("b_hi", b_hi - expr.b_hi);
        cb.add_constraint("b_lo", b_lo - expr.b_lo);
        cb.add_constraint("c_hi", c_hi - expr.c_hi);
        cb.add_constraint("c_lo", c_lo - expr.c_lo);
        cb.add_constraint("d_hi", d_hi - expr.d_hi);
        cb.add_constraint("d_lo", d_lo - expr.d_lo);

        // Todo. constrain a_limbs/b_limbs less than 2**64,and c_lo/d_lo less than 2**128
        // Todo. need to constrain on carry_hi?

        cb.add_constraints(bcb.constraints);
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        words: [U256; 4],
    ) -> Result<(), Error> {
        let (a, b, c, d) = (words[0], words[1], words[2], words[3]);

        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (c_hi, c_lo) = split_u256(&c);
        let (d_hi, d_lo) = split_u256(&d);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let carry_lo = (t0 + (t1 << 64u8) + c_lo).wrapping_sub(d_lo) >> 128;
        let carry_hi = (t2 + (t3 << 64u8) + c_hi + carry_lo).wrapping_sub(d_hi) >> 128;

        // assign value
        self.a_limbs
            .iter()
            .zip(a_limbs.iter())
            .map(|(cell, byte)| {
                cell.assign(region, offset, Some(F::from((*byte).unchecked_as_u64())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.b_limbs
            .iter()
            .zip(b_limbs.iter())
            .map(|(cell, byte)| {
                cell.assign(region, offset, Some(F::from((*byte).unchecked_as_u64())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.c_hi
            .assign(region, offset, Some(F::from_u128(c_hi.unchecked_as_u128())))?;
        self.c_lo
            .assign(region, offset, Some(F::from_u128(c_lo.unchecked_as_u128())))?;
        self.d_hi
            .assign(region, offset, Some(F::from_u128(d_hi.unchecked_as_u128())))?;
        self.d_lo
            .assign(region, offset, Some(F::from_u128(d_lo.unchecked_as_u128())))?;

        self.carry_lo
            .iter()
            .zip(carry_lo.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Some(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_hi
            .iter()
            .zip(carry_hi.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Some(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}
