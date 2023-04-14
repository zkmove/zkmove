// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBitwise, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::BYTES_NUM;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct BitAnd<F: FieldExt> {
    _value_a: Cell<F>,
    _value_b: Cell<F>,
    _value_c: Cell<F>,
    _bytes: [Cell<F>; BYTES_NUM],
    _bytes_operand_1: [Cell<F>; BYTES_NUM],
    _bytes_operand_2: [Cell<F>; BYTES_NUM],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for BitAnd<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        //bit and
        let cond = cells.conditions[Opcode::BitAnd.index()].expression.clone();

        LookupBitwise::lookup_bitwise(
            cells,
            Opcode::BitAnd,
            &mut lookups.bitwise_lookups,
            cond.clone(),
        );

        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::BitAnd,
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
        BinaryOp::assign_bitwise_op(region, offset, step, rw_operations, cells)?;

        Ok(())
    }
}
