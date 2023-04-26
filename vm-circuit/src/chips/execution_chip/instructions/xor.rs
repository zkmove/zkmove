// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBitwise, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
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
pub struct Xor<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
    bytes: Vec<Cell<F>>,
    bytes_operand_1: Vec<Cell<F>>,
    bytes_operand_2: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Xor<F> {
    const NAME: &'static str = "XOR";

    const OPCODE: Opcode = Opcode::Xor;
    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        //xor
        let cond = cells.conditions[Opcode::Xor.index()].expression.clone();

        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();
        let bytes = cb.query_n_cells(BYTES_NUM);
        let bytes_operand_1 = cb.query_n_cells(BYTES_NUM);
        let bytes_operand_2 = cb.query_n_cells(BYTES_NUM);

        let lookup_bitwise = LookupBitwise {
            bytes: bytes.clone(),
            bytes_operand_1: bytes_operand_1.clone(),
            bytes_operand_2: bytes_operand_2.clone(),
        };
        LookupBitwise::lookup_bitwise(
            &lookup_bitwise,
            Opcode::Xor,
            &mut lookups.bitwise_lookups,
            cond.clone(),
        );

        let binary_op = BinaryOp {
            value_a: value_a.clone(),
            value_b: value_b.clone(),
            value_c: value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cells, cb, cond.clone());
        BinaryOp::lookup_binary_op(cells, &binary_op, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Xor,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
            value_a,
            value_b,
            value_c,
            bytes,
            bytes_operand_1,
            bytes_operand_2,
        }
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

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();
        let bytes = cb.query_n_cells(BYTES_NUM);
        let bytes_operand_1 = cb.query_n_cells(BYTES_NUM);
        let bytes_operand_2 = cb.query_n_cells(BYTES_NUM);

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
