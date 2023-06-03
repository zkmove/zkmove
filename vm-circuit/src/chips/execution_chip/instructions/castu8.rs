// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{LookupBytecode, UnaryOp};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{assign_to_cells, Cell, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::NUM_OF_BYTES_U8;

#[derive(Clone, Debug)]
pub struct CastU8<F: FieldExt> {
    value_a: Cell<F>,
    value_c: Cell<F>,
    bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> InstructionGadget<F> for CastU8<F> {
    const NAME: &'static str = "CASTU8";

    const OPCODE: Opcode = Opcode::CastU8;
    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.opcode_selector([Self::OPCODE]);

        let x = self.value_a.expression.clone();
        let out = self.value_c.expression.clone();

        // x = out
        let constraint = cond.clone() * (x - out.clone());
        cb.add_constraint("cast u8", constraint);

        // range check for out
        let bytes_1 = FieldBytes::from(self.bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let constraint = cond.clone() * (out - bytes_1);
        cb.add_constraint("cast u8 range check", constraint);

        let unary_op = UnaryOp {
            value_a: self.value_a.clone(),
            value_c: self.value_c.clone(),
        };
        UnaryOp::constrain_unary_op(cells, cb, cond.clone());
        UnaryOp::lookup_unary_op(cells, &unary_op, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::CastU8,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
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

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        let cast_result = op.value().value().ok_or_else(|| {
            error!("cast_result is None");
            Error::Synthesis
        })?;

        assign_to_cells(region, offset, Some(cast_result), &self.bytes)?;
        // let result_bytes: [u8; 32] = cast_result
        //     .to_repr()
        //     .as_ref()
        //     .try_into()
        //     .expect("Field fits into 256 bits");
        // for (index, byte) in self.bytes.iter().enumerate() {
        //     byte.assign(region, offset, Some(F::from(result_bytes[index] as u64)))?;
        // }

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.alloc_cell();
        let value_c = cb.alloc_cell();
        let bytes = cb.alloc_n_cells(BYTES_NUM);

        Self {
            value_a,
            value_c,
            bytes,
        }
    }
}
