// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Expression;
use movelang::value_ext::{ValueHeader, LOWER_FIELD_OFFSET, UPPER_FIELD_OFFSET};
use types::Field;

use super::get_field_from_op;

/// there are 2 cells to suport u256. each for 128 bit
#[derive(Clone, Debug)]
pub struct WordCells<F: Field> {
    pub hi: Cell<F>,
    pub lo: Cell<F>,
}

impl<F: Field> WordCells<F> {
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
        rw_operations: &RWOperations,
        op_index: usize,
    ) -> Result<(), Error> {
        let f = get_field_from_op(rw_operations, op_index + UPPER_FIELD_OFFSET)?;
        self.hi.assign(region, offset, Some(f))?;
        let f = get_field_from_op(rw_operations, op_index + LOWER_FIELD_OFFSET)?;
        self.lo.assign(region, offset, Some(f))?;
        Ok(())
    }

    pub(crate) fn lookup_stack_pop(
        &self,
        cb: &mut ConstraintBuilder<F>,
        stack_size: Expression<F>,
        op_index: Expression<F>,
    ) {
        cb.add_lookup(
            "stack pop word's header",
            RWLookup::stack_pop(
                op_index.clone(),
                stack_size.clone(),
                0u64.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "stack pop word lower field",
            RWLookup::stack_pop(
                op_index.clone() + LOWER_FIELD_OFFSET.expr(),
                stack_size.clone(),
                LOWER_FIELD_OFFSET.expr(),
                self.lo.expression.clone(),
            ),
        );
        cb.add_lookup(
            "stack pop word upper field",
            RWLookup::stack_pop(
                op_index + UPPER_FIELD_OFFSET.expr(),
                stack_size,
                UPPER_FIELD_OFFSET.expr(),
                self.hi.expression.clone(),
            ),
        );
    }

    pub(crate) fn lookup_stack_push(
        &self,
        cb: &mut ConstraintBuilder<F>,
        stack_size: Expression<F>,
        op_index: Expression<F>,
    ) {
        cb.add_lookup(
            "stack push word's header",
            RWLookup::stack_push(
                op_index.clone(),
                stack_size.clone(),
                0u64.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "stack push word lower field",
            RWLookup::stack_push(
                op_index.clone() + LOWER_FIELD_OFFSET.expr(),
                stack_size.clone(),
                LOWER_FIELD_OFFSET.expr(),
                self.lo.expression.clone(),
            ),
        );
        cb.add_lookup(
            "stack push word upper field",
            RWLookup::stack_push(
                op_index + UPPER_FIELD_OFFSET.expr(),
                stack_size,
                UPPER_FIELD_OFFSET.expr(),
                self.hi.expression.clone(),
            ),
        );
    }
}
