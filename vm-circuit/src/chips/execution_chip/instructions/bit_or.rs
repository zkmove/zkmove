// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBitwise, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct BitOr<F: FieldExt> {
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
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::BitOr, 0.expr());
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
        let bytes = cb.alloc_n_cells(BYTES_NUM);
        let bytes_operand_1 = cb.alloc_n_cells(BYTES_NUM);
        let bytes_operand_2 = cb.alloc_n_cells(BYTES_NUM);

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
