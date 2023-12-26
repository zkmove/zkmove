// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::comparison::ComparisonGadget;
use crate::chips::math_gadget::lt::LtGadget;
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::Error;
use movelang::utility::convert_u256_to_field;
use movelang::value_ext::LEN_OF_SIMPLE_VALUE;
use types::Field;

use super::common::get_u256_from_op;
use super::common::word_gadget::WordCells;

#[derive(Clone, Debug)]
pub struct Lt<F: Field> {
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
    comparison_hi: ComparisonGadget<F, 16>,
    lt_lo: LtGadget<F, 16>,
}

impl<F: Field> InstructionGadget<F> for Lt<F> {
    const NAME: &'static str = "LT";

    const OPCODE: Opcode = Opcode::Lt;
    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        //Lt

        // lt is 0 or 1
        let (hi_lt, hi_eq) = self.comparison_hi.expr();
        let lt = hi_lt + hi_eq * self.lt_lo.expr();
        let constraint = lt.clone() * (1u64.expr() - lt.clone());
        cb.add_constraint("Lt: output is bool", constraint);

        // lt == value_c
        cb.add_constraint(
            "Lt: upper field is zero",
            self.value_c.hi.expression.clone(),
        );
        cb.add_constraint(
            "Lt: lower field equal to lt output",
            lt - self.value_c.lo.expression.clone(),
        );

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Lt, 0u64.expr());
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

        // assign value to Lt/Comparison gadget
        let lhs = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let rhs = get_u256_from_op(rw_operations, step.gc)?;
        let lhs_fe = convert_u256_to_field::<F>(&lhs);
        let rhs_fe = convert_u256_to_field::<F>(&rhs);
        self.comparison_hi
            .assign(region, offset, lhs_fe[0], rhs_fe[0])?;
        self.lt_lo.assign(region, offset, lhs_fe[1], rhs_fe[1])?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);
        let comparison_hi = ComparisonGadget::construct(
            cb,
            value_a.hi.expression.clone(),
            value_b.hi.expression.clone(),
        );
        let lt_lo = LtGadget::construct(
            cb,
            value_a.lo.expression.clone(),
            value_b.lo.expression.clone(),
        );

        Self {
            value_a,
            value_b,
            value_c,
            comparison_hi,
            lt_lo,
        }
    }
}
