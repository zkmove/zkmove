// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::HeaderCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::error;
use movelang::value_ext::LEN_OF_REFERENCE_VALUE;
use std::convert::TryInto;
use std::ops::Index;

#[derive(Clone, Debug)]
pub(crate) struct RefValCells<F>([Cell<F>; LEN_OF_REFERENCE_VALUE]);

impl<F: FieldExt> RefValCells<F> {
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let cells: [Cell<F>; LEN_OF_REFERENCE_VALUE] = cb
            .alloc_n_cells(LEN_OF_REFERENCE_VALUE)
            .try_into()
            .expect("allocate cells for ref val should not fail.");
        Self(cells)
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
    ) -> Result<(), Error> {
        for i in 0..LEN_OF_REFERENCE_VALUE {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            self.0[i].assign(region, offset, op.value().value())?;
        }

        Ok(())
    }

    pub(crate) fn as_inner(&self) -> &[Cell<F>; LEN_OF_REFERENCE_VALUE] {
        &self.0
    }

    pub(crate) fn addr_ext(&self) -> &Cell<F> {
        self.0.last().expect("addr_ext should not be None.")
    }
}

impl<F: FieldExt> Index<usize> for RefValCells<F> {
    type Output = Cell<F>;

    fn index(&self, i: usize) -> &Cell<F> {
        &self.0[i]
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RefValGadget<F> {
    pub(crate) cells: RefValCells<F>,
    pub(crate) header_cells: HeaderCells<F>,
}

impl<F: FieldExt> RefValGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            cells: RefValCells::construct(cb),
            header_cells: HeaderCells::construct(cb),
        }
    }
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(op_index).ok_or(Error::Synthesis)?;
        let header_value = op.value().value().ok_or_else(|| {
            error!("header value is None");
            Error::Synthesis
        })?;

        self.cells.assign(region, offset, rw_operations, op_index)?;
        self.header_cells.assign(region, offset, header_value)?;
        Ok(())
    }

    pub(crate) fn configure(&self, cb: &mut ConstraintBuilder<F>) {
        // check word header
        self.constrain_header(cb, self.cells.0[0].expression.clone());

        // check ref val length
        let constraint = (LEN_OF_REFERENCE_VALUE as u64).expr()
            - self.header_cells.flattened_len.expression.clone();
        cb.add_constraint("check ref val length", constraint);
    }

    fn constrain_header(&self, cb: &mut ConstraintBuilder<F>, header: Expression<F>) {
        let constraint = header
            - self.header_cells.flattened_len.expression.clone()
            - self.header_cells.len.expression.clone() * 2u64.pow(16).expr();
        cb.add_constraint("check word header", constraint);

        //TODO: flattened_len and len belong to [0, 2^16)
    }
}
