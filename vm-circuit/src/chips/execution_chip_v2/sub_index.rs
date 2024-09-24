use crate::chips::execution_chip_v2::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip_v2::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::utils::from_limbs;
use crate::chips::execution_chip_v2::value::NUM_OF_BYTES_U256;
use crate::chips::utils::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::types::sub_index::SubIndex;
use aptos_move_witnesses::types::sub_index::N_BITS_ONE_LIMB;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use types::Field;

pub(crate) const DEPTH_POW_OF_ONE_LEVEL: u64 = 2u64.pow(N_BITS_ONE_LIMB as u32);

fn get_limbs_from_bytes<F: Field, const N_LIMB: usize>(
    bytes: &[Cell<F>],
) -> [Expression<F>; N_LIMB] {
    assert!(
        bytes.len() >= 2 * N_LIMB,
        "bytes slice is too small for the number of limbs"
    );
    (0..N_LIMB)
        .map(|i| bytes[i * 2 + 1].expr() * 2u64.pow(8).expr() + bytes[i * 2].expr())
        .collect::<Vec<_>>()
        .try_into()
        .expect("Failed to get limbs")
}

#[derive(Clone, Debug)]
pub(crate) struct Membership<F, const N_LIMB: usize> {
    header_bytes: [Cell<F>; NUM_OF_BYTES_U256],
    header_limbs: [Expression<F>; N_LIMB],
    member_bytes: [Cell<F>; NUM_OF_BYTES_U256],
    member_limbs: [Expression<F>; N_LIMB],
    mask: [Cell<F>; N_LIMB],
    reverse_header_limbs: [Cell<F>; N_LIMB],
    reverse_header_member_diff: Cell<F>,
}

impl<F: Field, const N_LIMB: usize> Membership<F, N_LIMB> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let header_bytes = cb.query_bytes();
        let member_bytes = cb.query_bytes();

        let header_limbs = get_limbs_from_bytes(&header_bytes);
        let member_limbs = get_limbs_from_bytes(&member_bytes);

        let mask = cb.query_bools();
        let reverse_header_limbs = cb.query_cells();
        let reverse_header_member_diff = cb.query_cell();

        Self {
            header_bytes,
            header_limbs,
            member_bytes,
            member_limbs,
            mask,
            reverse_header_limbs,
            reverse_header_member_diff,
        }
    }

    pub(crate) fn configure(
        &self,
        cb: &mut ConstraintBuilderV2<F>,
        header_sub_index: Expression<F>,
        member_sub_index: Expression<F>,
    ) {
        cb.require_equal(
            "header_sub_index == from_limbs(header_limbs)",
            header_sub_index.clone(),
            from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&self.header_limbs),
        );
        cb.require_equal(
            "member_sub_index == from_limbs(&member_limbs)",
            member_sub_index.clone(),
            from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&self.member_limbs),
        );

        for i in 0..N_LIMB {
            cb.require_zero(
                "mask[i] * (header_limbs[i] * reverse_header_limbs[i] - 1) == 0",
                self.mask[i].expr()
                    * (self.header_limbs[i].expr() * self.reverse_header_limbs[i].expr()
                        - 1u64.expr()),
            );
            cb.require_zero(
                "(1 - mask[i]) * header_limbs[i] == 0",
                (1u64.expr() - self.mask[i].expr()) * self.header_limbs[i].expr(),
            );
            cb.require_zero(
                "mask[i] * (header_limbs[i] - member_limbs[i]) == 0",
                self.mask[i].expr() * (self.header_limbs[i].expr() - self.member_limbs[i].expr()),
            );
        }

        // member should not equal to header
        let header_member_diff = member_sub_index - header_sub_index;
        cb.require_zero(
            "header_member_diff * reverse_header_member_diff - 1 == 0",
            header_member_diff * self.reverse_header_member_diff.expr() - 1u64.expr(),
        );
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        header_sub_index: u128,
        member_sub_index: u128,
    ) -> Result<(), Error> {
        // assign header bytes
        let header_sub_index_bytes = F::from_u128(header_sub_index).to_repr();
        for (idx, byte) in self.header_bytes.iter().enumerate() {
            byte.assign(
                region,
                offset,
                Value::known(F::from(header_sub_index_bytes[idx] as u64)),
            )?;
        }

        // assign member bytes
        let member_sub_index_bytes = F::from_u128(member_sub_index).to_repr();
        for (idx, byte) in self.member_bytes.iter().enumerate() {
            byte.assign(
                region,
                offset,
                Value::known(F::from(member_sub_index_bytes[idx] as u64)),
            )?;
        }

        // assign mask and reverse_header_limbs
        let header_limbs = SubIndex::from(header_sub_index).to_vec();
        for (i, &limb) in header_limbs.iter().enumerate().take(N_LIMB) {
            let mask = limb != 0;
            self.mask[i].assign(region, offset, Value::known(F::from(mask as u64)))?;

            let reverse_limb = F::from(limb as u64).invert().unwrap_or(F::ZERO);
            self.reverse_header_limbs[i].assign(region, offset, Value::known(reverse_limb))?;
        }

        // assign reverse of header_member_diff
        let header_member_diff = F::from_u128(member_sub_index) - F::from_u128(header_sub_index);
        let reverse_header_member_diff = header_member_diff.invert().unwrap_or(F::ZERO);
        self.reverse_header_member_diff.assign(
            region,
            offset,
            Value::known(reverse_header_member_diff),
        )?;

        Ok(())
    }
}

/// Extended SubIndex used for manipulate sub_index, like concat
#[derive(Clone, Debug)]
pub(crate) struct ExtendedSubIndex<F, const N_LIMB: usize> {
    sub_index: Expression<F>,
    bytes: [Cell<F>; NUM_OF_BYTES_U256],
    limbs: [Expression<F>; N_LIMB],
    mask: [Cell<F>; N_LIMB],
    reverse_limb: Cell<F>, // reverse of limbs[depth-1]
}
impl<F: Field, const N_LIMB: usize> ExtendedSubIndex<F, N_LIMB> {
    pub(crate) fn construct(cb: &mut ConstraintBuilderV2<F>, sub_index: Expression<F>) -> Self {
        let s = Self::construct_without_configure(cb, sub_index);
        s.configure(cb);
        s
    }

    pub(crate) fn construct_without_configure(
        cb: &mut ConstraintBuilderV2<F>,
        sub_index: Expression<F>,
    ) -> Self {
        let bytes = cb.query_bytes();
        let limbs = get_limbs_from_bytes(&bytes);
        let mask = cb.query_bools();
        let reverse_limb = cb.query_cell();
        Self {
            sub_index,
            bytes,
            limbs,
            mask,
            reverse_limb,
        }
    }
    pub(crate) fn configure(&self, cb: &mut ConstraintBuilderV2<F>) {
        cb.require_equal(
            "sub_index == from_limbs(limbs)",
            self.sub_index.clone(),
            from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&self.limbs),
        );

        let sum_mask: Expression<F> = self.mask.iter().map(|c| c.expr()).sum();
        cb.require_zero(
            "sum(mask[i]) == 1 when sub_index != 0",
            self.sub_index.clone() * (sum_mask - 1u64.expr()),
        );

        for i in 0..N_LIMB {
            cb.require_zero(
                "if mask[i] == 1, limbs[i] != 0",
                self.mask[i].expr()
                    * (self.limbs[i].clone() * self.reverse_limb.expr() - 1u64.expr()),
            );
        } // this also implies "when sub_index == 0, mask[i] == 0"

        for i in 0..(N_LIMB - 1) {
            cb.require_zero(
                "mask[i] * limbs[i+1] == 0",
                self.mask[i].expr() * self.limbs[i + 1].clone(),
            );
        }
    }

    /// Return the parent sub_index of self sub_index.
    /// Notice: If self sub_index is zero, parent will be zero too.
    pub(crate) fn get_parent_sub_index(&self) -> Expression<F> {
        let parent_sub_index_limbs = self
            .limbs
            .iter()
            .enumerate()
            .map(|(i, c)| c.expr() * (1u64.expr() - self.mask[i].expr()))
            .collect::<Vec<_>>();
        from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&parent_sub_index_limbs)
    }

    /// Trim tailing zeros of sub_index and concat with another.
    pub(crate) fn concat(&self, other: Expression<F>) -> Expression<F> {
        let sum_mask: Expression<F> = self.mask.iter().map(|c| c.expr()).sum();
        let depth_pow = from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&self.mask)
            * DEPTH_POW_OF_ONE_LEVEL.expr()
            + (1.expr() - sum_mask);
        // depth = 0, mask = [0,0,0,0], depth_pow = 0 * 2^16 + 1 - 0
        // depth = 1, mask =[1,0,0,0], depth_pow = 1 * 2^16 + 1 - 1,
        // depth = 2, mask =[0,1,0,0], depth_pow = (0+1*2^16) * 2^16 + 1 -1 ,
        // depth = 3, mask =[0,0,1,0], depth_pow = (0+0*(2^16)+1*(2^16)^2) * 2^16 + 1-1,
        self.sub_index.expr() + other * depth_pow
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        ref_sub_index: F,
    ) -> Result<(), Error> {
        // assign bytes
        let ref_sub_index_bytes = ref_sub_index.to_repr();
        for (idx, byte) in self.bytes.iter().enumerate() {
            byte.assign(
                region,
                offset,
                Value::known(F::from(ref_sub_index_bytes[idx] as u64)),
            )?;
        }

        // assign mask
        let depth = SubIndex::from(ref_sub_index.get_lower_128()).depth();
        for i in 0..N_LIMB {
            let mask = depth != 0 && i == depth - 1;
            self.mask[i].assign(region, offset, Value::known(F::from(mask as u64)))?;
        }

        // assign reverse of limbs[depth-1]
        let reverse_limb = if depth != 0 {
            // limb = limbs[depth-1]
            let limb = (ref_sub_index_bytes[depth * 2 - 1] as u64) * 256
                + ref_sub_index_bytes[depth * 2 - 2] as u64;
            F::from(limb).invert().expect("invert should not fail")
        } else {
            F::ZERO
        };
        self.reverse_limb
            .assign(region, offset, Value::known(reverse_limb))?;

        Ok(())
    }
}

/// Used to get the reverse of a sub_index. For example,
///
/// let a = [3,2,0,0];
/// assert_eq!(a.to_u128(), 0x20003);
///
/// let b = [0,0,2,3]; // the reverse of a
/// assert_eq!(b.to_u128(), 0x0003000200000000);
///
#[derive(Clone, Debug)]
pub(crate) struct SubIndexReverse<F, const N_LIMB: usize> {
    sub_index: Expression<F>,
    limbs: [Cell<F>; N_LIMB],
}
impl<F: Field, const N_LIMB: usize> SubIndexReverse<F, N_LIMB> {
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

        cb.require_equal(
            format!("{}, sub_index == from_limbs(limbs)", name),
            sub_index.clone(),
            from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&limbs),
        );

        Self { sub_index, limbs }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        let reverse_limbs = self.limbs.iter().rev().collect::<Vec<_>>();
        from_limbs::expr::<_, _, N_BITS_ONE_LIMB>(&reverse_limbs)
    }
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        sub_index: &SubIndex,
    ) -> Result<(), Error> {
        let vec = sub_index.to_vec();
        debug_assert!(vec.len() == N_LIMB);
        for (i, v) in vec.into_iter().enumerate() {
            self.limbs[i].assign(region, offset, Value::known(F::from(v as u64)))?;
        }
        Ok(())
    }
}
