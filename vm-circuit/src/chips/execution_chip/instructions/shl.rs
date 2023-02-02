use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::marker::PhantomData;

pub struct Shl<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Shl<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::Shl.index()].expression.clone();
        let lhs = cells.value_a.expression.clone();
        let rhs = cells.value_b.expression.clone();
        let divisor = cells.auxiliary_1.expression.clone();
        let dividend = cells.value_c.expression.clone();

        // TODO: should we constraint that rhs is in u8 range?
        // TODO: Add overflow constraints.
        // quotient * divisor + remainder = dividend
        constraints.push((
            "shl: lhs * pow(2, rhs) = result",
            cond.clone() * (lhs * divisor.clone() - dividend),
        ));

        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Shl,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond.clone(),
        );

        lookups.pow2_lookups.push((
            Pow2Lookup {
                pow: rhs,
                pow_result: divisor,
            },
            cond,
        ));
    }

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, cells)?;
        // It's ok to slice here, as BinaryOp::assign_binary_op already check the range.
        let ops = &rw_operations.0[step.gc..=step.gc + 2];
        let b = &ops[0].value();
        let pow2_of_b = F::from_u128(2).pow(&[b.value().unwrap().get_lower_32() as u64, 0, 0, 0]);
        cells.auxiliary_1.assign(region, offset, Some(pow2_of_b))?;

        Ok(())
    }
}
