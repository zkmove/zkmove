pub(crate) mod base;
pub(crate) mod borrow_loc;
pub(crate) mod br_bool;
pub(crate) mod ld;
pub(crate) mod pack;
pub(crate) mod read_ref;
pub(crate) mod vec_swap;
pub use borrow_loc::*;
pub use br_bool::*;
pub use ld::*;
pub use pack::*;
pub use read_ref::*;
pub use vec_swap::*;

use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::utils::from_bytes;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use strum_macros::EnumIter;
use types::Field;

#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ExecutionState {
    Start,
    BrTrue,
    BrFalse,
    VecSwapStage1,
    VecSwapStage2,
    VecSwapStage3,
    VecSwapStage4,
    Stop,
    Nop,
    MutBorrowLoc,
    ImmBorrowLoc,
    LdFalse,
    LdTrue,
    LdU128,
    LdU64,
    LdU32,
    LdU16,
    LdU8,
    Pack,
    ReadRefStage1,
    ReadRefStage2,
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

#[derive(Clone, Debug)]
pub(crate) struct SubIndexGadget<F: Field, const N_LIMB: usize> {
    bytes: [Cell<F>; 16],
    mask: [Cell<F>; N_LIMB],
    depth_pow2: Cell<F>,   //2^(depth * (128 / N_LIMB))
    reverse_limb: Cell<F>, //reverse of limb[depth-1]
}
impl<F: Field, const N_LIMB: usize> SubIndexGadget<F, N_LIMB> {
    /// common constraints for move a filed under a reference, for example(N_LIMB = 8):
    /// ref_sub_index = [3,2,0,0,0,0,0,0], field_sub_index = [4,0,0,0,0,0,0,0], depth = 2,
    /// reslult = [3,2,4,0,0,0,0,0]
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        ref_sub_index: Expression<F>,
        field_sub_index: Expression<F>,
        result: Expression<F>,
        name: &'static str,
    ) -> Self {
        let bytes = cb.query_bytes();
        let mask = cb.query_bytes();
        let depth_pow2 = cb.query_cell();
        let reverse_limb = cb.query_cell();

        cb.require_equal(
            format!("{}, ref_sub_index == from_bytes(&bytes)", name),
            ref_sub_index.clone(),
            from_bytes::expr(&bytes),
        );

        for i in 0..N_LIMB {
            cb.require_boolean(format!("{}, mask[i] == 0 | 1", name), mask[i].expr());
        }
        cb.require_zero(
            format!("{}, sum(mask[i]) == 1", name),
            mask.iter().fold(1u64.expr(), |acc, cell| acc - cell.expr()),
        );

        let mut limbs = Vec::new();
        match N_LIMB {
            8 => {
                for i in 0..N_LIMB {
                    limbs[i] = bytes[2 * i + 1].expr() * 2u64.pow(8).expr() + bytes[2 * i].expr();
                }
            }
            16 => {
                for i in 0..N_LIMB {
                    limbs[i] = bytes[i].expr();
                }
            }
            _ => unimplemented!(),
        }

        //if mask[0] == 1 { ref_sub_index == 0; }
        cb.require_zero(
            format!("{}, mask[0] * ref_sub_index", name),
            mask[0].expr() * ref_sub_index.clone(),
        );
        for i in 1..N_LIMB {
            // if mask[i] == 1 { limbs[i] == 0; }
            cb.require_zero(
                format!("{}, mask[i] * limbs[i]", name),
                mask[i].expr() * limbs[i].clone(),
            );
            // if mask[i] == 1 { limbs[i-1] != 0; }
            cb.require_zero(
                format!("{}, !mask[i] * limbs[i-1]", name),
                mask[i].expr() * (limbs[i - 1].clone() * reverse_limb.expr() - 1u64.expr()),
            );
        }

        cb.require_equal(
            format!("{}, depth_pow2 = from_bytes(&mask)", name),
            depth_pow2.expr(),
            from_bytes::expr(&mask),
        );

        cb.require_equal(
            format!(
                "{}, result == ref_sub_index + field_sub_index * depth_pow2",
                name
            ),
            result,
            ref_sub_index + field_sub_index * depth_pow2.expr(),
        );

        Self {
            bytes,
            mask,
            depth_pow2,
            reverse_limb,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        ref_sub_index: u128,
        depth: usize,
    ) -> Result<(), Error> {
        let ref_sub_index_bytes = F::from_u128(ref_sub_index).to_repr();
        for (idx, byte) in self.bytes.iter().enumerate() {
            byte.assign(
                region,
                offset,
                Value::known(F::from(ref_sub_index_bytes[idx] as u64)),
            )?;
        }

        let depth_pow2 = F::from_u128(2u128.pow((depth * (128 / N_LIMB)).try_into().unwrap()));
        self.depth_pow2
            .assign(region, offset, Value::known(depth_pow2))?;
        let depth_pow2_bytes = depth_pow2.to_repr();
        for (idx, mask) in self.mask.iter().enumerate() {
            mask.assign(
                region,
                offset,
                Value::known(F::from(depth_pow2_bytes[idx] as u64)),
            )?;
        }

        let reverse_limb = if depth != 0 {
            F::from(ref_sub_index_bytes[depth - 1] as u64)
                .invert()
                .unwrap_or(F::ZERO)
        } else {
            F::ZERO
        };
        self.reverse_limb
            .assign(region, offset, Value::known(reverse_limb))?;

        Ok(())
    }
}
