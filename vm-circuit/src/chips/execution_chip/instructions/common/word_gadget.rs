// Copyright (c) zkMove Authors

use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::Cell;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
use movelang::value_ext::{LOWER_FIELD_OFFSET, UPPER_FIELD_OFFSET};

/// there are 2 cells to suport u256. each for 128 bit
#[derive(Clone, Debug)]
pub struct WordCell<F: FieldExt> {
    pub hi: Cell<F>,
    pub lo: Cell<F>,
}

impl<F: FieldExt> WordCell<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        Self {
            hi: cb.alloc_cell(),
            lo: cb.alloc_cell(),
        }
    }

    pub(crate) fn expr(&self) -> (Expression<F>, Expression<F>) {
        (self.hi.expression.clone(), self.lo.expression.clone())
    }

    #[allow(dead_code)]
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
    ) -> Result<(), Error> {
        let op = rw_operations
            .0
            .get(op_index + UPPER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        self.hi.assign(region, offset, op.value().value())?;
        let op = rw_operations
            .0
            .get(op_index + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        self.lo.assign(region, offset, op.value().value())?;
        Ok(())
    }
}
