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
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
use std::convert::TryInto;

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct CastU128<F: FieldExt> {
    value_a: WordCells<F>,
    value_c: WordCells<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for CastU128<F> {
    const NAME: &'static str = "CASTU128";

    const OPCODE: Opcode = Opcode::CastU128;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let (input_hi, input_lo) = self.value_a.expr();
        let (out_hi, out_lo) = self.value_c.expr();

        // input = out
        cb.add_constraint("cast u128 hi", input_hi);
        cb.add_constraint("cast u128 hi", out_hi);
        cb.add_constraint("cast u128 lo", input_lo - out_lo.clone());

        // range check for out. u128 at out_lo
        let bytes_16 = FieldBytes::from(self.bytes.clone()).expr_with_n(NUM_OF_BYTES_U128);
        cb.add_constraint("cast u128 range check", out_lo - bytes_16);

        let unary_op = UnaryOp {
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb);
        UnaryOp::lookup_unary_op(cb, cells, &unary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::CastU128, 0.expr());
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
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };

        UnaryOp::assign_unary_op(region, offset, step, rw_operations, &unary_op)?;

        // only out_lo need to take care
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
        let value_a = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            value_a,
            value_c,
            bytes,
        }
    }
}
