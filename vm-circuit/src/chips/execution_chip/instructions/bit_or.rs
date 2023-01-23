// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBitwise, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::convert::TryInto;
use std::marker::PhantomData;

pub struct BitOr<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for BitOr<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //bit and
        let cond = cells.conditions[Opcode::BitOr.index()].expression.clone();

        LookupBitwise::lookup_bitwise(
            cells,
            Opcode::BitOr,
            &mut lookups.bitwise_lookups,
            cond.clone(),
        );

        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::BitOr,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond,
        );
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, cells)?;

        // store operand 1 at bytes cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc + 1)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes_operand_1.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store operand 2 at bytes cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes_operand_2.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store result at bytes cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc + 2)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        Ok(())
    }
}
