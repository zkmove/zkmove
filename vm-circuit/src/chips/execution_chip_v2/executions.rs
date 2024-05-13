pub(crate) mod base;
pub(crate) mod borrow_field;
pub(crate) mod borrow_loc;
pub(crate) mod br_bool;
pub(crate) mod call;
pub(crate) mod ld;
pub(crate) mod pack;
pub(crate) mod read_ref;
pub(crate) mod vec_swap;
pub(crate) mod write_ref;
pub use borrow_field::*;
pub use borrow_loc::*;
pub use br_bool::*;
pub use call::*;
pub use ld::*;
pub use pack::*;
pub use write_ref::*;

use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::utils::from_limbs;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use halo2_proofs::plonk::{Error, Expression};
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
    VecSwapStage5,
    VecSwapStage6,
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
    MutBorrowField,
    ImmBorrowField,
    WriteRefStage1,
    WriteRefStage2,
    WriteRefStage3,
    WriteRefStage4,
    CallWithNoArgs,
    CallWithArgs,
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
pub(crate) struct MembershipGadget<F: Field, const N_LIMB: usize> {
    header_limbs: [Cell<F>; N_LIMB],
    field_limbs: [Cell<F>; N_LIMB],
    mask: [Cell<F>; N_LIMB],
    reverse_limbs: [Cell<F>; N_LIMB],
    reverse_header_field_diff: Cell<F>,
}
impl<F: Field, const N_LIMB: usize> MembershipGadget<F, N_LIMB> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_u16())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let field_limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_u16())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mask: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_bool())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let reverse_limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_cell())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let reverse_header_field_diff = cb.query_cell();

        Self {
            header_limbs,
            field_limbs,
            mask,
            reverse_limbs,
            reverse_header_field_diff,
        }
    }

    pub(crate) fn configure(
        &self,
        cb: &mut ConstraintBuilderV2<F>,
        header_sub_index: Expression<F>,
        field_sub_index: Expression<F>,
        name: &'static str,
    ) {
        cb.require_equal(
            format!("{}, header_sub_index == from_limbs(header_limbs)", name),
            header_sub_index.clone(),
            from_limbs::expr::<_, _, 16>(&self.header_limbs),
        );
        cb.require_equal(
            format!("{}, field_sub_index == from_limbs(&field_limbs)", name),
            field_sub_index.clone(),
            from_limbs::expr::<_, _, 16>(&self.field_limbs),
        );

        for i in 0..N_LIMB {
            cb.require_zero(
                format!(
                    "{}, mask[i] * (header_limbs[i] * reverse_limbs[i] - 1) == 0",
                    name
                ),
                self.mask[i].expr()
                    * (self.header_limbs[i].expr() * self.reverse_limbs[i].expr() - 1u64.expr()),
            );
            cb.require_zero(
                format!("{}, (1 - mask[i]) * header_limbs[i] == 0", name),
                (1u64.expr() - self.mask[i].expr()) * self.header_limbs[i].expr(),
            );
            cb.require_zero(
                format!(
                    "{}, mask[i] * (header_limbs[i] - field_limbs[i]) == 0",
                    name
                ),
                self.mask[i].expr() * (self.header_limbs[i].expr() - self.field_limbs[i].expr()),
            );
        }

        //we need field_sub_index != header_sub_index
        let header_field_diff = field_sub_index - header_sub_index;
        cb.require_zero(
            format!(
                "{}, header_field_diff * reverse_header_field_diff - 1 == 0",
                name
            ),
            header_field_diff * self.reverse_header_field_diff.expr() - 1u64.expr(),
        );
    }
}

pub(crate) const DEPTH_POW_OF_ONE_LEVEL: u64 = 2u64.pow(16);

/// Extended SubIndex used for manipulate sub_index, like concat
#[derive(Clone, Debug)]
pub(crate) struct ExtendedSubIndex<F: Field, const N_LIMB: usize> {
    sub_index: Expression<F>,
    limbs: [Cell<F>; N_LIMB],
    mask: [Cell<F>; N_LIMB],
    reverse_limb: Cell<F>,
}
impl<F: Field, const N_LIMB: usize> ExtendedSubIndex<F, N_LIMB> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        name: impl AsRef<str>,
        sub_index: Expression<F>,
    ) -> Self {
        let limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_u16())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mask: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_bool())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let reverse_limb = cb.query_cell();
        let depth_pow2 = cb.query_cell();
        let name = name.as_ref();
        cb.require_equal(
            format!("{}, sub_index == from_limbs(limbs)", name),
            sub_index.clone(),
            from_limbs::expr::<_, _, 16>(&limbs),
        );
        cb.require_equal(
            format!("{}, sum(mask[i]) == 1", name),
            mask.iter().map(|c| c.expr()).sum(),
            1u64.expr(),
        );

        for i in 0..N_LIMB {
            cb.require_zero(
                format!("{}, mask[i] * limbs[i] != 0", name),
                mask[i].expr() * (limbs[i].expr() * reverse_limb.expr() - 1u64.expr()),
            );
        }
        for i in 0..(N_LIMB - 1) {
            cb.require_zero(
                format!("{}, mask[i] * limbs[i+1] == 0", name),
                mask[i].expr() * limbs[i + 1].expr(),
            );
        }

        Self {
            sub_index,
            limbs,
            mask,
            reverse_limb,
        }
    }

    pub(crate) fn get_depth_pow(&self) -> Expression<F> {
        from_limbs::expr::<_, _, 16>(&self.mask) * DEPTH_POW_OF_ONE_LEVEL.expr()
    }

    pub(crate) fn get_parent_sub_index(&self) -> Expression<F> {
        let parent_sub_index_limbs = self
            .limbs
            .iter()
            .enumerate()
            .map(|(i, c)| c.expr() * (1u64.expr() - self.mask[i].expr()))
            .collect::<Vec<_>>();
        from_limbs::expr::<_, _, 16>(&parent_sub_index_limbs)
    }

    /// TODO: change to a better name
    /// concat sub_index with another sub_index, and return the resulted sub_index
    /// current sub_index  = [3,2,0,0,0,0,0,0] of depth = 2,
    ///  concat other_sub_index = [4,1,0,0,0,0,0,0],
    /// expected_sub_index = [3,2,4,1,0,0,0,0]
    pub(crate) fn concat_sub_index(&self, other_sub_index: Expression<F>) -> Expression<F> {
        self.sub_index.expr() + other_sub_index * self.get_depth_pow()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        ref_sub_index: u128,
        depth: usize,
    ) -> Result<(), Error> {
        // let ref_sub_index_bytes = F::from_u128(ref_sub_index).to_repr();
        // for (idx, byte) in self.bytes.iter().enumerate() {
        //     byte.assign(
        //         region,
        //         offset,
        //         Value::known(F::from(ref_sub_index_bytes[idx] as u64)),
        //     )?;
        // }
        //
        // let depth_pow2 = F::from_u128(2u128.pow((depth * (128 / N_LIMB)).try_into().unwrap()));
        // self.depth_pow2
        //     .assign(region, offset, Value::known(depth_pow2))?;
        // let depth_pow2_bytes = depth_pow2.to_repr();
        // for (idx, mask) in self.mask.iter().enumerate() {
        //     mask.assign(
        //         region,
        //         offset,
        //         Value::known(F::from(depth_pow2_bytes[idx] as u64)),
        //     )?;
        // }
        //
        // let reverse_limb = if depth != 0 {
        //     F::from(ref_sub_index_bytes[depth - 1] as u64)
        //         .invert()
        //         .unwrap_or(F::ZERO)
        // } else {
        //     F::ZERO
        // };
        // self.reverse_limb
        //     .assign(region, offset, Value::known(reverse_limb))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SubIndexDepth<F: Field, const N_LIMB: usize> {
    sub_index: Expression<F>,
    limbs: [Cell<F>; N_LIMB],
    mask: [Cell<F>; N_LIMB],
    reverse_limbs: [Cell<F>; N_LIMB],
}
impl<F: Field, const N_LIMB: usize> SubIndexDepth<F, N_LIMB> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        sub_index: Expression<F>,
        name: &'static str,
    ) -> Self {
        let limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_u16())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mask: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_bool())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let reverse_limbs: [Cell<F>; N_LIMB] = (0..N_LIMB)
            .map(|_| cb.query_cell())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        cb.require_equal(
            format!("{}, sub_index == from_limbs(limbs)", name),
            sub_index.clone(),
            from_limbs::expr::<_, _, 16>(&limbs),
        );
        for i in 0..N_LIMB {
            cb.require_zero(
                format!("{}, mask[i] * (limbs[i] * reverse_limbs[i] - 1) == 0", name),
                mask[i].expr() * (limbs[i].expr() * reverse_limbs[i].expr() - 1u64.expr()),
            );
            cb.require_zero(
                format!("{}, (1 - mask[i]) * limbs[i] == 0", name),
                (1u64.expr() - mask[i].expr()) * limbs[i].expr(),
            );
        }

        Self {
            sub_index,
            limbs,
            mask,
            reverse_limbs,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.mask.iter().map(|c| c.expr()).sum()
    }
}
