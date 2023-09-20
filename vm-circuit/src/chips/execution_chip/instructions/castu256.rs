// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::NUM_OF_BYTES_U128;
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET, UPPER_FIELD_OFFSET};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct CastU256<F: FieldExt> {
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
    bytes_hi: Vec<Cell<F>>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for CastU256<F> {
    const NAME: &'static str = "CASTU256";

    const OPCODE: Opcode = Opcode::CastU256;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let input_hi = self.value_a_hi.expression.clone();
        let input_lo = self.value_a_lo.expression.clone();
        let out_hi = self.value_c_hi.expression.clone();
        let out_lo = self.value_c_lo.expression.clone();

        // x = out
        cb.add_constraint("cast u256 hi", input_hi - out_hi.clone());
        cb.add_constraint("cast u256 lo", input_lo - out_lo.clone());

        // range check for out
        let bytes_32 = FieldBytes::from(self.bytes_hi.clone()).expr_with_n(NUM_OF_BYTES_U128);
        cb.add_constraint("cast u256 range check 0", out_hi - bytes_32);
        let bytes_32 = FieldBytes::from(self.bytes.clone()).expr_with_n(NUM_OF_BYTES_U128);
        cb.add_constraint("cast u256 range check 1", out_lo - bytes_32);

        let unary_op = UnaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb);
        UnaryOp::lookup_unary_op(cb, cells, &unary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::CastU256, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let unary_op = UnaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        UnaryOp::assign_unary_op(region, offset, step, rw_operations, &unary_op)?;

        // value_c upper 128 bit
        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_SIMPLE_VALUE + UPPER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let cast_result = op.value().value().ok_or_else(|| {
            error!("cast_result is None");
            Error::Synthesis
        })?;

        let result_bytes: [u8; 32] = cast_result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in self.bytes_hi.iter().enumerate() {
            byte.assign(region, offset, Some(F::from(result_bytes[index] as u64)))?;
        }

        // value_c lower 128 bit
        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_SIMPLE_VALUE + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let cast_result = op.value().value().ok_or_else(|| {
            error!("cast_result is None");
            Error::Synthesis
        })?;

        let result_bytes: [u8; 32] = cast_result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in self.bytes.iter().enumerate() {
            byte.assign(region, offset, Some(F::from(result_bytes[index] as u64)))?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a_hi = cb.alloc_cell();
        let value_a_lo = cb.alloc_cell();
        let value_c_hi = cb.alloc_cell();
        let value_c_lo = cb.alloc_cell();
        let bytes_hi = cb.alloc_n_cells(BYTES_NUM);
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            value_a_hi,
            value_a_lo,
            value_c_hi,
            value_c_lo,
            bytes_hi,
            bytes,
        }
    }
}
