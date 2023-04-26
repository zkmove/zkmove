// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{ArithOverflow, BinaryOp, LookupBytecode};
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
pub struct Mul<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Mul<F> {
    const NAME: &'static str = "MUL";

    const OPCODE: Opcode = Opcode::Mul;
    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        let cond = cells.conditions[Opcode::Mul.index()].expression.clone();

        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();
        let bytes = cb.query_n_cells(BYTES_NUM);

        let lhs = value_a.expression.clone();
        let rhs = value_b.expression.clone();
        let out = value_c.expression.clone();
        let constraint = cond.clone() * (lhs * rhs - out.clone());
        cb.add_constraint("mul", constraint);

        ArithOverflow::constrain_range_check(cells, bytes.clone(), cb, cond.clone(), out);
        ArithOverflow::lookup_arith_op(
            cells,
            &mut lookups.arith_op_lookups,
            cond.clone(),
            cells.auxiliary_1.expression.clone(),
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
            Opcode::Mul,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
        Self {
            value_a,
            value_b,
            value_c,
            bytes,
        }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };

        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        let op = rw_operations.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        let value = op.value();
        ArithOverflow::assign_num_of_bytes(region, offset, cells, self.bytes.clone(), value)?;

        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();
        let bytes = cb.query_n_cells(BYTES_NUM);

        Self {
            value_a,
            value_b,
            value_c,
            bytes,
        }
    }
}
