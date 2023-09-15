// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
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
use std::convert::TryInto;

use super::common::word_gadget::WordCell;

#[derive(Clone, Debug)]
pub struct Ge<F: FieldExt> {
    value_a: WordCell<F>,
    value_b: WordCell<F>,
    value_c: WordCell<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Ge<F> {
    const NAME: &'static str = "GE";

    const OPCODE: Opcode = Opcode::Ge;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //Ge

        let lhs = self.value_a.lo.expression.clone();
        let rhs = self.value_b.lo.expression.clone();
        let out = self.value_c.lo.expression.clone();
        let diff = FieldBytes::from(self.bytes.clone()).expr();
        let range = F::from(2).pow(&[(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);

        // out is 0 or 1
        let constraint = out.clone() * (1.expr() - out.clone());
        cb.add_constraint("out value is bool", constraint);

        // there is only 16 bytes for diff, so diff is in range 2 ^ 128
        // if lhs >= rhs, then out = 1, diff = lhs - rhs
        // if lhs < rhs, then out == 0, diff = lhs - rhs + range
        let constraint = (lhs - rhs) + (1.expr() - out) * range - diff;
        cb.add_constraint("Ge", constraint);

        let binary_op = BinaryOp {
            value_a_hi: self.value_a.hi.clone(),
            value_a_lo: self.value_a.lo.clone(),
            value_b_hi: self.value_b.hi.clone(),
            value_b_lo: self.value_b.lo.clone(),
            value_c_hi: self.value_c.hi.clone(),
            value_c_lo: self.value_c.lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Ge, 0.expr());
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a_hi: self.value_a.hi.clone(),
            value_a_lo: self.value_a.lo.clone(),
            value_b_hi: self.value_b.hi.clone(),
            value_b_lo: self.value_b.lo.clone(),
            value_c_hi: self.value_c.hi.clone(),
            value_c_lo: self.value_c.lo.clone(),
        };

        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;

        let diff = aux_value.value().ok_or_else(|| {
            error!("auxiliary_1 value is None");
            Error::Synthesis
        })?;

        let diff_bytes: [u8; 32] = diff
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in self.bytes.iter().enumerate() {
            byte.assign(region, offset, Some(F::from(diff_bytes[index] as u64)))?;
        }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCell::<F>::construct(cb);
        let value_b = WordCell::<F>::construct(cb);
        let value_c = WordCell::<F>::construct(cb);
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            value_a,
            value_b,
            value_c,
            bytes,
        }
    }
}
