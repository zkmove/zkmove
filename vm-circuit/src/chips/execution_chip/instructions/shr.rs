use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use movelang::value::Value;
use std::marker::PhantomData;
use std::ops::Rem;

pub struct Shr<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Instructions<F> for Shr<F> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::Shr.index()].expression.clone();
        let dividend = cells.value_a.expression.clone();
        let shift_bits = cells.value_b.expression.clone();
        let quotient = cells.value_c.expression.clone();
        let divisor = cells.auxiliary_1.expression.clone();
        let reminder = cells.auxiliary_2.expression.clone();
        // TODO: should we constraint that rhs is in u8 range?
        // TODO: Add overflow constraints.

        // quotient * divisor + remainder = dividend
        constraints.push((
            "shr: quotient * divisor + remainder = dividend",
            cond.clone() * (quotient * divisor.clone() + reminder - dividend),
        ));

        // TODO: reminder < divisor
        // TODO: divisor != 0

        BinaryOp::constrain_binary_op(cells, constraints, cond.clone());
        BinaryOp::lookup_binary_op(cells, &mut lookups.rw_lookups, cond.clone());
        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::Shr,
            0.expr(),
            &mut lookups.bytecode_lookups,
            cond.clone(),
        );
        lookups.pow2_lookups.push((
            Pow2Lookup {
                pow: shift_bits,
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
        debug_assert!(
            step.gc + 2 < rw_operations.0.len(),
            "expect 3 rw operations"
        );
        let ops = &rw_operations.0[step.gc..=step.gc + 2];
        debug_assert_eq!(
            ops.iter().map(|op| op.rw()).collect::<Vec<_>>(),
            vec![RW::READ, RW::READ, RW::WRITE]
        );
        for (op, cell) in ops
            .iter()
            .zip([&cells.value_b, &cells.value_a, &cells.value_c])
        {
            cell.assign(region, offset, op.value().value())?;
        }

        let b = &ops[0].value();
        let pow2_of_b = F::from_u128(2).pow(&[b.value().unwrap().get_lower_32() as u64, 0, 0, 0]);
        cells.auxiliary_1.assign(region, offset, Some(pow2_of_b))?;

        // reminder = a % (2^b)
        let reminder = {
            let a = ops[1].value();
            let two_power_rhs = Value::new(pow2_of_b, a.ty())?;
            a.rem(two_power_rhs)?
        };
        cells.auxiliary_2.assign(region, offset, reminder.value())?;

        Ok(())
    }
}
