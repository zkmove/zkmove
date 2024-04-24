pub(crate) mod base;
pub(crate) mod borrow_field;
pub(crate) mod borrow_loc;
pub(crate) mod br_bool;
pub(crate) mod ld;
pub(crate) mod pack;
pub(crate) mod read_ref;
pub(crate) mod vec_swap;
pub use borrow_field::*;
pub use borrow_loc::*;
pub use br_bool::*;
pub use ld::*;
pub use pack::*;

use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::utils::from_bytes;
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
    header_bytes: [Cell<F>; 16],
    field_bytes: [Cell<F>; 16],
    mask: [Cell<F>; N_LIMB],
    reverse_limbs: [Cell<F>; N_LIMB],
    reverse_header_field_diff: Cell<F>,
}
impl<F: Field, const N_LIMB: usize> MembershipGadget<F, N_LIMB> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_bytes = cb.query_bytes();
        let field_bytes = cb.query_bytes();
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
            header_bytes,
            field_bytes,
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
            format!(
                "{}, header_sub_index == from_bytes(&self.header_bytes)",
                name
            ),
            header_sub_index.clone(),
            from_bytes::expr(&self.header_bytes),
        );
        cb.require_equal(
            format!("{}, field_sub_index == from_bytes(&self.field_bytes)", name),
            field_sub_index.clone(),
            from_bytes::expr(&self.field_bytes),
        );
        let header_limbs = (0..N_LIMB)
            .map(|i| match N_LIMB {
                8 => {
                    self.header_bytes[2 * i + 1].expr() * 2u64.pow(8).expr()
                        + self.header_bytes[2 * i].expr()
                }
                16 => self.header_bytes[i].expr(),
                _ => unimplemented!(),
            })
            .collect::<Vec<_>>();
        let field_limbs = (0..N_LIMB)
            .map(|i| match N_LIMB {
                8 => {
                    self.field_bytes[2 * i + 1].expr() * 2u64.pow(8).expr()
                        + self.field_bytes[2 * i].expr()
                }
                16 => self.field_bytes[i].expr(),
                _ => unimplemented!(),
            })
            .collect::<Vec<_>>();

        for i in 0..N_LIMB {
            cb.require_zero(
                format!(
                    "{}, self.mask[i] * (header_limbs[i] * self.reverse_limbs[i] - 1) == 0",
                    name
                ),
                self.mask[i].expr()
                    * (header_limbs[i].clone() * self.reverse_limbs[i].expr() - 1u64.expr()),
            );
            cb.require_zero(
                format!("{}, (1 - self.mask[i]) * header_limbs[i] == 0", name),
                (1u64.expr() - self.mask[i].expr()) * header_limbs[i].clone(),
            );
            cb.require_zero(
                format!(
                    "{}, self.mask[i] * (header_limbs[i] - field_limbs[i]) == 0",
                    name
                ),
                self.mask[i].expr() * (header_limbs[i].clone() - field_limbs[i].clone()),
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
    header_sub_index: Expression<F>,
    header_bytes: [Cell<F>; 16],
    mask_bytes: [Cell<F>; 16],
    reverse_limb: Cell<F>,
    depth_pow2: Cell<F>, //2^(depth * (128 / N_LIMB))
}
impl<F: Field, const N_LIMB: usize> ExtendedSubIndex<F, N_LIMB> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        name: impl AsRef<str>,
        header_sub_index: Expression<F>,
    ) -> Self {
        let header_bytes = cb.query_bytes(); //TODO: query_u16_cells()
        let mask_bytes: [Cell<F>; 16] = (0..16)
            .map(|_| cb.query_bool())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let reverse_limb = cb.query_cell();
        let depth_pow2 = cb.query_cell();
        let name = name.as_ref();
        cb.require_equal(
            format!("{}, sub_index_a == from_bytes(&self.header_bytes)", name),
            header_sub_index.clone(),
            from_bytes::expr(&header_bytes),
        );

        let limbs = (0..N_LIMB)
            .map(|i| match N_LIMB {
                8 => {
                    header_bytes[2 * i + 1].expr() * 2u64.pow(8).expr() + header_bytes[2 * i].expr()
                }
                16 => header_bytes[i].expr(),
                _ => unimplemented!(),
            })
            .collect::<Vec<_>>();
        let mask_limbs = (0..N_LIMB)
            .map(|i| match N_LIMB {
                8 => mask_bytes[2 * i + 1].expr() * 2u64.pow(8).expr() + mask_bytes[2 * i].expr(),
                16 => mask_bytes[i].expr(),
                _ => unimplemented!(),
            })
            .collect::<Vec<_>>();
        cb.require_equal(
            format!("{}, sum(mask[i]) == 1", name),
            mask_limbs.iter().cloned().sum(),
            1u64.expr(),
        );

        //constrain: if mask[0] == 1 { sub_index_a == 0; }
        cb.require_zero(
            format!("{}, mask_limbs[0] * sub_index_a", name),
            mask_limbs[0].clone() * header_sub_index.clone(),
        );
        for i in 1..N_LIMB {
            cb.require_zero(
                format!("{}, mask_limbs[i] * limbs[i] == 0", name),
                mask_limbs[i].clone() * limbs[i].clone(),
            );
            cb.require_zero(
                format!("{}, mask_limbs[i] * limbs[i-1] != 0", name),
                mask_limbs[i].clone() * (limbs[i - 1].clone() * reverse_limb.expr() - 1u64.expr()),
            );
        }

        cb.require_equal(
            format!("{}, depth_pow2 = from_bytes(&mask)", name),
            depth_pow2.expr(),
            from_bytes::expr(&mask_bytes),
        );

        Self {
            header_sub_index,
            header_bytes,
            mask_bytes,
            reverse_limb,
            depth_pow2,
        }
    }

    pub(crate) fn get_depth_pow(&self) -> Expression<F> {
        self.depth_pow2.expr()
    }

    /// TODO: change to a better name
    /// concat the header's sub_index with another sub_index, and return the resulted sub_index
    /// current header_sub_index  = [3,2,0,0,0,0,0,0] of depth = 2,
    ///  concat other_sub_index = [4,1,0,0,0,0,0,0],
    /// expected_sub_index = [3,2,4,1,0,0,0,0]
    pub(crate) fn concat_sub_index(&self, other_sub_index: Expression<F>) -> Expression<F> {
        self.header_sub_index.expr() + other_sub_index * self.depth_pow2.expr()
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
