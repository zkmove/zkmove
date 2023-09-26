// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBitwise, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use movelang::value::NUM_OF_BYTES_U256;

use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct BitOr<F: FieldExt> {
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
    bytes: Vec<Cell<F>>,
    bytes_operand_1: Vec<Cell<F>>,
    bytes_operand_2: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for BitOr<F> {
    const NAME: &'static str = "BITOR";

    const OPCODE: Opcode = Opcode::BitOr;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //bit and

        let lookup_bitwise = LookupBitwise {
            bytes: self.bytes.clone(),
            bytes_operand_1: self.bytes_operand_1.clone(),
            bytes_operand_2: self.bytes_operand_2.clone(),
        };
        LookupBitwise::lookup_bitwise(cb, &lookup_bitwise, Opcode::BitOr);

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::BitOr, 0u64.expr());
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
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        let lookup_bitwise = LookupBitwise {
            bytes: self.bytes.clone(),
            bytes_operand_1: self.bytes_operand_1.clone(),
            bytes_operand_2: self.bytes_operand_2.clone(),
        };
        BinaryOp::assign_bitwise_op(region, offset, step, rw_operations, &lookup_bitwise)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);

        // bytes[i] = bytes_operand_1[i] | bytes_operand_2[i]
        // each bytes need 2 fields(4 bit each) and totally 64 cells
        let bytes = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);
        let bytes_operand_1 = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);
        let bytes_operand_2 = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);

        Self {
            value_a,
            value_b,
            value_c,
            bytes,
            bytes_operand_1,
            bytes_operand_2,
        }
    }
}
