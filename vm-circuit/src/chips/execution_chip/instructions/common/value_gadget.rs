// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::HeaderCells;
use crate::chips::execution_chip::param::word_capacity;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::error;

#[derive(Clone, Debug)]
pub(crate) struct GadgetCells<F> {
    pub(crate) word: Vec<Cell<F>>,
    pub(crate) word_mask: Vec<Cell<F>>,
    pub(crate) word_addr_ext: Vec<Cell<F>>,
}

impl<F: FieldExt> GadgetCells<F> {
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let word_cap = word_capacity();

        // alloc cell
        let word = cb.alloc_n_cells(word_cap);
        let word_mask = cb.alloc_n_cells(word_cap);
        let word_addr_ext = cb.alloc_n_cells(word_cap);

        Self {
            word,
            word_mask,
            word_addr_ext,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
        flattened_value_len: usize,
    ) -> Result<(), Error> {
        if flattened_value_len > word_capacity() {
            // TODO: a better place to do word cap check is in "fn from(value: &Value<F>) -> Word<F>"
            // but we have no capacity set at the moment. Considering move word.rs to the folder "witness".
            error!(
                "word element num is {:?}, exceeds word capacity {:?}",
                flattened_value_len,
                word_capacity()
            );
            return Err(Error::Synthesis);
        }

        for (i, _) in self.word.iter().enumerate().take(flattened_value_len) {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            self.word[i].assign(region, offset, op.value().value())?;
            self.word_mask[i].assign(region, offset, Some(F::zero()))?;
            self.word_addr_ext[i].assign(region, offset, Some(F::from(op.address_ext() as u64)))?;
        }

        for (i, _) in self.word.iter().enumerate().skip(flattened_value_len) {
            self.word_mask[i].assign(region, offset, Some(F::one()))?;
            self.word_addr_ext[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ValueGadget<F> {
    pub(crate) cells: GadgetCells<F>,
    pub(crate) header_cells: HeaderCells<F>,
}

impl<F: FieldExt> ValueGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            cells: GadgetCells::construct(cb),
            header_cells: HeaderCells::construct(cb),
        }
    }
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
        flattened_value_len: usize,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(op_index).ok_or(Error::Synthesis)?;
        let header_value = op.value().value().ok_or_else(|| {
            error!("header value is None");
            Error::Synthesis
        })?;

        self.cells
            .assign(region, offset, rw_operations, op_index, flattened_value_len)?;
        self.header_cells.assign(region, offset, header_value)?;
        Ok(())
    }

    pub(crate) fn configure(&self, cb: &mut ConstraintBuilder<F>, flattened_value_len: Expression<F>) {
        // check word header
        self.constrain_header(cb, self.cells.word[0].expression.clone());

        // check word mask
        self.constrain_mask(
            cb,
            &self.cells.word_mask,
            self.header_cells.flattened_len.expression.clone(),
        );

        // check word element number
        let constraint = flattened_value_len - self.header_cells.flattened_len.expression.clone();
        cb.add_constraint("check word element number", constraint);

        // TODO: check addr_ext
        // 1.strict monotonic increment (exclude item not been masked)
    }

    fn constrain_mask(
        &self,
        cb: &mut ConstraintBuilder<F>,
        masks: &[Cell<F>],
        flattened_len: Expression<F>,
    ) {
        // mask is 0 or 1
        let zero_or_one = masks
            .iter()
            .map(|mask| {
                (
                    "mask is zero or one",
                    (mask.expression.clone() - 1.expr()) * mask.expression.clone(),
                )
            })
            .collect::<Vec<_>>();
        cb.add_constraints(zero_or_one);

        // mask is monotonic increasing
        for (i, _) in masks.iter().enumerate().skip(1) {
            let delta = masks[i].expression.clone() - masks[i - 1].expression.clone();
            let constraint = delta.clone() * (1.expr() - delta);
            cb.add_constraint("mask monotonic increase", constraint);
        }

        //  sum of mask is flattened_len
        let sum = (word_capacity() as u64).expr() - flattened_len;
        let constraint = masks
            .iter()
            .fold(sum, |acc, mask| acc - mask.expression.clone());
        cb.add_constraint("check mask sum", constraint);
    }

    fn constrain_header(&self, cb: &mut ConstraintBuilder<F>, header: Expression<F>) {
        let constraint = header
            - self.header_cells.flattened_len.expression.clone()
            - self.header_cells.len.expression.clone() * 2u64.pow(16).expr();
        cb.add_constraint("check word header", constraint);

        //TODO: flattened_len and len belong to [0, 2^16)
    }
}
