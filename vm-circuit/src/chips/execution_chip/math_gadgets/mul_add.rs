use crate::chips::execution_chip::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip::utils::{from_bytes, pow_of_two_expr};
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use gadgets::util::Expr;
use halo2_proofs::{
    circuit::Value,
    plonk::{ErrorFront as Error, Expression},
};
use move_core_types::u256::U256;
use std::ops::Shl;
use types::Field;
use utility::u256::{split_u256, split_u256_limb64};

const MAX_RADIX_BYTES: usize = 9;

#[derive(Clone, Debug)]
pub(crate) struct MulAddExprs<F> {
    pub a_limbs: [Expression<F>; 4],
    pub b_limbs: [Expression<F>; 4],
    pub c_hi: Expression<F>,
    pub c_lo: Expression<F>,
    pub d_hi: Expression<F>,
    pub d_lo: Expression<F>,
}

/// The algorithm is adapted from PSE's zkEVM implementation.
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
///   t0 + t1 * 2^64 + c_lo = d_lo + carry_lo * 2^128
///   t2 + t3 * 2^64 + c_hi + carry_lo = d_hi + carry_hi * 2^128
///
/// Last, we sum the parts that are higher than 256-bit in the multiplication
/// into overflow
///   overflow = carry_hi + a1 * b3 + a2 * b2 + a3 * b1 + a2 * b3 + a3 * b2
///              + a3 * b3
///
#[derive(Clone, Debug)]
pub(crate) struct MulAddGadget<F> {
    carry_lo: [Cell<F>; MAX_RADIX_BYTES],
    carry_hi: [Cell<F>; MAX_RADIX_BYTES],
    is_zero_overflow: IsZeroGadget<F>,
}

impl<F: Field> MulAddGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>, cells: &MulAddExprs<F>) -> Self {
        let carry_lo = cb.query_bytes();
        let carry_hi = cb.query_bytes();
        let carry_lo_expr = from_bytes::expr(&carry_lo);
        let carry_hi_expr = from_bytes::expr(&carry_hi);

        let a_limbs = &cells.a_limbs;
        let b_limbs = &cells.b_limbs;
        let t0 = a_limbs[0].expr() * b_limbs[0].expr();
        let t1 = a_limbs[0].expr() * b_limbs[1].expr() + a_limbs[1].expr() * b_limbs[0].expr();
        let t2 = a_limbs[0].expr() * b_limbs[2].expr()
            + a_limbs[1].expr() * b_limbs[1].expr()
            + a_limbs[2].expr() * b_limbs[0].expr();
        let t3 = a_limbs[0].expr() * b_limbs[3].expr()
            + a_limbs[1].expr() * b_limbs[2].expr()
            + a_limbs[2].expr() * b_limbs[1].expr()
            + a_limbs[3].expr() * b_limbs[0].expr();
        let overflow = carry_hi_expr.clone()
            + a_limbs[1].expr() * b_limbs[3].expr()
            + a_limbs[2].expr() * b_limbs[2].expr()
            + a_limbs[2].expr() * b_limbs[3].expr()
            + a_limbs[3].expr() * b_limbs[1].expr()
            + a_limbs[3].expr() * b_limbs[2].expr()
            + a_limbs[3].expr() * b_limbs[3].expr();
        let is_zero_overflow = IsZeroGadget::construct(cb, overflow);

        cb.require_equal(
            "(a * b)_lo + c_lo == d_lo + carry_lo * 2^128",
            t0 + t1 * pow_of_two_expr(64) + cells.c_lo.expr(),
            cells.d_lo.expr() + carry_lo_expr.clone() * pow_of_two_expr(128),
        );
        cb.require_equal(
            "(a * b)_hi + c_hi + carry_lo == d_hi + carry_hi * 2^128",
            t2 + t3 * pow_of_two_expr(64) + cells.c_hi.expr() + carry_lo_expr,
            cells.d_hi.expr() + carry_hi_expr.clone() * pow_of_two_expr(128),
        );

        Self {
            carry_lo,
            carry_hi,
            is_zero_overflow,
        }
    }

    pub(crate) fn overflow(&self) -> Expression<F> {
        1u64.expr() - self.is_zero_overflow.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        a: U256,
        b: U256,
        c: U256,
        d: U256,
    ) -> Result<bool, Error> {
        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (c_lo, c_hi) = split_u256(&c);
        let (d_lo, d_hi) = split_u256(&d);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let carry_lo = (t0 + t1.shl(64u8) + c_lo)
            .checked_sub(d_lo)
            .unwrap_or(U256::zero())
            >> 128;
        let carry_hi = (t2 + t3.shl(64u8) + c_hi + carry_lo)
            .checked_sub(d_hi)
            .unwrap_or(U256::zero())
            >> 128;
        let overflow = carry_hi
            + a_limbs[1] * b_limbs[3]
            + a_limbs[2] * b_limbs[2]
            + a_limbs[2] * b_limbs[3]
            + a_limbs[3] * b_limbs[1]
            + a_limbs[3] * b_limbs[2]
            + a_limbs[3] * b_limbs[3];

        self.carry_lo
            .iter()
            .zip(carry_lo.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_hi
            .iter()
            .zip(carry_hi.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(overflow != U256::zero())
    }
}
