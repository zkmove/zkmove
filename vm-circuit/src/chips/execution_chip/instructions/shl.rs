use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value_ext::LOWER_FIELD_OFFSET;

#[derive(Clone, Debug)]
pub struct Shl<F: FieldExt> {
    value_a_hi: Cell<F>,
    value_a_lo: Cell<F>,
    value_b_hi: Cell<F>,
    value_b_lo: Cell<F>,
    value_c_hi: Cell<F>,
    value_c_lo: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for Shl<F> {
    const NAME: &'static str = "SHL";

    const OPCODE: Opcode = Opcode::Shl;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let lhs = self.value_a_lo.expression.clone();
        let rhs = self.value_b_lo.expression.clone();
        let divisor = cells.auxiliary_1.expression.clone();
        let dividend = self.value_c_lo.expression.clone();

        // TODO: should we constraint that rhs is in u8 range?
        // TODO: Add overflow constraints.
        // quotient * divisor + remainder = dividend
        cb.add_constraint(
            "shl: lhs * pow(2, rhs) = result",
            lhs * divisor.clone() - dividend,
        );

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
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Shl, 0.expr());

        cb.add_lookup(
            "pow2 lookups for opcode shl",
            Pow2Lookup {
                pow: rhs,
                pow_result: divisor,
            },
        );
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
            value_a_hi: self.value_a_hi.clone(),
            value_a_lo: self.value_a_lo.clone(),
            value_b_hi: self.value_b_hi.clone(),
            value_b_lo: self.value_b_lo.clone(),
            value_c_hi: self.value_c_hi.clone(),
            value_c_lo: self.value_c_lo.clone(),
        };
        BinaryOp::assign_binary_op(region, offset, step, rw_operations, &binary_op)?;

        // b is U8 type data, lower field used.
        let op = rw_operations
            .0
            .get(step.gc + LOWER_FIELD_OFFSET)
            .ok_or(Error::Synthesis)?;
        let b = op.value().value().ok_or_else(|| {
            error!("header value is None");
            Error::Synthesis
        })?;
        let pow2_of_b = F::from_u128(2).pow(&[b.get_lower_32() as u64, 0, 0, 0]);
        cells.auxiliary_1.assign(region, offset, Some(pow2_of_b))?;

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

        Self {
            value_a_hi,
            value_a_lo,
            value_b_hi,
            value_b_lo,
            value_c_hi,
            value_c_lo,
        }
    }
}
