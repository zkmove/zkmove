// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::HeaderCells;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value_ext::{ValueHeader, LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
use std::convert::TryInto;

use super::get_field_from_op;

#[derive(Clone, Debug)]
pub(crate) struct SimpleValueCells<F>([Cell<F>; LEN_OF_SIMPLE_VALUE]);

impl<F: FieldExt> SimpleValueCells<F> {
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let cells: [Cell<F>; LEN_OF_SIMPLE_VALUE] = cb
            .alloc_n_cells(LEN_OF_SIMPLE_VALUE)
            .try_into()
            .expect("allocate cells for simple value should not fail.");
        Self(cells)
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        op_index: usize,
    ) -> Result<(), Error> {
        for i in 0..LEN_OF_SIMPLE_VALUE {
            let f = get_field_from_op(rw_operations, op_index + i)?;
            self.0[i].assign(region, offset, Some(f))?;
        }

        Ok(())
    }

    pub(crate) fn value(&self) -> &Cell<F> {
        // by so far, which is used with lower field by caller.
        // TODO. need to take care upper field?
        self.0
            .get(LOWER_FIELD_OFFSET)
            .expect("value should not be None.")
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SimpleValueGadget<F> {
    pub(crate) cells: SimpleValueCells<F>,
    pub(crate) header_cells: HeaderCells<F>,
}

impl<F: FieldExt> SimpleValueGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        Self {
            cells: SimpleValueCells::construct(cb),
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
        let header_value = get_field_from_op(rw_operations, op_index)?;
        self.cells.assign(region, offset, rw_operations, op_index)?;
        self.header_cells.assign(region, offset, header_value)?;
        Ok(())
    }

    pub(crate) fn configure(&self, cb: &mut ConstraintBuilder<F>) {
        // check word header
        self.constrain_header(cb, self.cells.0[0].expression.clone());

        // check simple val length
        let constraint = (LEN_OF_SIMPLE_VALUE as u64).expr()
            - self.header_cells.flattened_len.expression.clone();
        cb.add_constraint("check simple value length", constraint);
    }

    fn constrain_header(&self, cb: &mut ConstraintBuilder<F>, header: Expression<F>) {
        let constraint = header
            - self.header_cells.flattened_len.expression.clone()
            - self.header_cells.len.expression.clone() * 2u64.pow(16).expr();
        cb.add_constraint("check word header", constraint);

        //TODO: flattened_len and len belong to [0, 2^16)
    }

    pub(crate) fn lookup_stack_pop(
        &self,
        cb: &mut ConstraintBuilder<F>,
        stack_size: Expression<F>,
        op_index: Expression<F>,
    ) {
        cb.add_lookup(
            "stack pop simple value's header",
            RWLookup::stack_pop(
                op_index.clone(),
                stack_size.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "stack pop simple value lower field",
            RWLookup::stack_pop(
                op_index + (LOWER_FIELD_OFFSET as u64).expr(),
                stack_size,
                (LOWER_FIELD_OFFSET as u64).expr(),
                self.cells.value().expression.clone(),
            ),
        );
        // TODO. need high filed?
        // cb.add_lookup(
        //     "stack pop simple value upper field",
        //     RWLookup::stack_pop(
        //         op_index + UPPER_FIELD_OFFSET.expr(),
        //         stack_size,
        //         UPPER_FIELD_OFFSET.expr(),
        //         self.value().expression.clone(),
        //     ),
        // );
    }

    pub(crate) fn lookup_stack_push(
        &self,
        cb: &mut ConstraintBuilder<F>,
        stack_size: Expression<F>,
        op_index: Expression<F>,
    ) {
        cb.add_lookup(
            "stack push simple vlaue's header",
            RWLookup::stack_push(
                op_index.clone(),
                stack_size.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "stack push simple value lower field",
            RWLookup::stack_push(
                op_index + (LOWER_FIELD_OFFSET as u64).expr(),
                stack_size,
                (LOWER_FIELD_OFFSET as u64).expr(),
                self.cells.value().expression.clone(),
            ),
        );
        // TODO. need to take care upper filed?
        // cb.add_lookup(
        //     "stack push simple value upper field",
        //     RWLookup::stack_push(
        //         op_index + UPPER_FIELD_OFFSET.expr(),
        //         stack_size,
        //         UPPER_FIELD_OFFSET.expr(),
        //         self.hi.expression.clone(),
        //     ),
        // );
    }
}
