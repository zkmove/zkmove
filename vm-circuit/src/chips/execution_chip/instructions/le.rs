// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
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

#[derive(Clone, Debug)]
pub struct Le<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for Le<F> {
    const NAME: &'static str = "LE";

    const OPCODE: Opcode = Opcode::Le;
    fn configure(
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> Self {
        //Le
        let cond = cells.conditions[Opcode::Le.index()].expression.clone();

        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();
        let bytes = cb.query_n_cells(BYTES_NUM);

        let lhs = value_a.expression.clone();
        let rhs = value_b.expression.clone();
        let out = value_c.expression.clone();
        let diff = FieldBytes::from(bytes.clone()).expr();
        let range = F::from(2).pow(&[(NUM_OF_BYTES_U128 * 8) as u64, 0, 0, 0]);

        // out is 0 or 1
        let constraint = cond.clone() * out.clone() * (1.expr() - out.clone());
        cb.add_constraint("out value is bool", constraint);

        // there is only 16 bytes for diff, so diff is in range 2 ^ 128
        // if lhs > rhs, then out = 0, diff = lhs - rhs
        // if lhs < rhs, then out == 1, diff = lhs - rhs + range
        // if lhs == rhs, then out == 1, diff = 0
        let constraint = cond.clone()
            * ((lhs.clone() - rhs.clone()) + out.clone() * range - diff)
            * (lhs - rhs + 1.expr() - out);
        cb.add_constraint("Le", constraint);

        let binary_op = BinaryOp {
            value_a: value_a.clone(),
            value_b: value_b.clone(),
            value_c: value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cells, cb, cond.clone());
        BinaryOp::lookup_binary_op(cells, &binary_op, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Le,
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
        _cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
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
}
