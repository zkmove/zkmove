use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub struct Shl<F: FieldExt> {
    value_a: Cell<F>,
    value_b: Cell<F>,
    value_c: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Shl<F> {
    const NAME: &'static str = "SHL";

    const OPCODE: Opcode = Opcode::Shl;

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        let cond = cells.conditions[Opcode::Shl.index()].expression.clone();

        let lhs = self.value_a.expression.clone();
        let rhs = self.value_b.expression.clone();
        let divisor = cells.auxiliary_1.expression.clone();
        let dividend = self.value_c.expression.clone();

        // TODO: should we constraint that rhs is in u8 range?
        // TODO: Add overflow constraints.
        // quotient * divisor + remainder = dividend
        cb.add_constraint(
            "shl: lhs * pow(2, rhs) = result",
            cond.clone() * (lhs * divisor.clone() - dividend),
        );

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cells, cb, cond.clone());
        BinaryOp::lookup_binary_op(cells, &binary_op, &mut lookups.rw_lookups, cond.clone());
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
        // It's ok to slice here, as BinaryOp::assign_binary_op already check the range.
        let ops = &rw_operations.0[step.gc..=step.gc + 2];
        let b = &ops[0].value();
        let pow2_of_b = F::from_u128(2).pow(&[b.value().unwrap().get_lower_32() as u64, 0, 0, 0]);
        cells.auxiliary_1.assign(region, offset, Some(pow2_of_b))?;

        Ok(())
    }

    fn probe(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = cb.query_cell();
        let value_b = cb.query_cell();
        let value_c = cb.query_cell();

        Self {
            value_a,
            value_b,
            value_c,
        }
    }
}
