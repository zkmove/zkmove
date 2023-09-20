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

#[derive(Clone, Debug)]
pub struct BitAnd<F: FieldExt> {
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_b_hi: Cell<F>,
    value_b_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
    bytes: Vec<Cell<F>>,
    bytes_operand_1: Vec<Cell<F>>,
    bytes_operand_2: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for BitAnd<F> {
    const NAME: &'static str = "BITAND";

    const OPCODE: Opcode = Opcode::BitAnd;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //bit and
        let lookup_bitwise = LookupBitwise {
            bytes: self.bytes.clone(),
            bytes_operand_1: self.bytes_operand_1.clone(),
            bytes_operand_2: self.bytes_operand_2.clone(),
        };
        LookupBitwise::lookup_bitwise(cb, &lookup_bitwise, Opcode::BitAnd);

        let binary_op = BinaryOp {
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::BitAnd, 0.expr());
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
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
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
        let value_a_hi = cb.alloc_cell();
        let value_a_lo = cb.alloc_cell();
        let value_b_hi = cb.alloc_cell();
        let value_b_lo = cb.alloc_cell();
        let value_c_hi = cb.alloc_cell();
        let value_c_lo = cb.alloc_cell();

        // bytes[i] = bytes_operand_1[i] & bytes_operand_2[i]
        // each bytes need 2 fields(4 bit each) and totally 64 cells
        let bytes = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);
        let bytes_operand_1 = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);
        let bytes_operand_2 = cb.alloc_n_cells(NUM_OF_BYTES_U256 * 2);

        Self {
            value_a_hi,
            value_a_lo,
            value_b_hi,
            value_b_lo,
            value_c_hi,
            value_c_lo,
            bytes,
            bytes_operand_1,
            bytes_operand_2,
        }
    }
}
