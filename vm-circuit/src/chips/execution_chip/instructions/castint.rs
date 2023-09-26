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
use movelang::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
use std::convert::TryInto;

use super::common::get_field_from_op;
use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct CastInt<F: FieldExt, const N_BYTES: usize> {
    value_a: WordCells<F>,
    value_c: WordCells<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt, const N_BYTES: usize> InstructionGadget<F> for CastInt<F, N_BYTES> {
    const NAME: &'static str = match N_BYTES {
        NUM_OF_BYTES_U8 => "CASTU8",
        NUM_OF_BYTES_U16 => "CASTU16",
        NUM_OF_BYTES_U32 => "CASTU32",
        NUM_OF_BYTES_U64 => "CASTU64",
        NUM_OF_BYTES_U128 => "CASTU128",
        _ => unreachable!(),
    };

    const OPCODE: Opcode = match N_BYTES {
        NUM_OF_BYTES_U8 => Opcode::CastU8,
        NUM_OF_BYTES_U16 => Opcode::CastU16,
        NUM_OF_BYTES_U32 => Opcode::CastU32,
        NUM_OF_BYTES_U64 => Opcode::CastU64,
        NUM_OF_BYTES_U128 => Opcode::CastU128,
        _ => unreachable!(),
    };
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let (input_hi, input_lo) = self.value_a.expr();
        let (out_hi, out_lo) = self.value_c.expr();

        // x = out
        cb.add_constraint("cast input hi", input_hi);
        cb.add_constraint("cast output hi", out_hi);
        cb.add_constraint("cast lo", input_lo - out_lo.clone());
        // range check for out.
        let bytes_1 = FieldBytes::from(self.bytes.clone()).expr_with_n(N_BYTES);
        cb.add_constraint("cast range check", out_lo - bytes_1);
        let unary_op = UnaryOp {
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb);
        UnaryOp::lookup_unary_op(cb, cells, &unary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Self::OPCODE, 0u64.expr());
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
        let cast_result = get_field_from_op(
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE + LOWER_FIELD_OFFSET,
        )?;

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
