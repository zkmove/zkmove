use crate::chips::execution_chip::instructions::common::{BinaryOp, LookupBytecode};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;

use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::lt::LtGadget;
use crate::chips::math_gadget::mul_add_words::{MulAddWordsGadget, MulAddWordsOp};
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::utility::{convert_u256_to_field, decode_field_to_u256};
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};

use super::common::word_gadget::WordCells;
use super::common::{get_field_from_op, get_u256_from_op};

#[derive(Clone, Debug)]
pub struct Shr<F: FieldExt> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
    rhs_less_than_128: LtGadget<F, 1>,
}

impl<F: FieldExt> InstructionGadget<F> for Shr<F> {
    const NAME: &'static str = "SHR";

    const OPCODE: Opcode = Opcode::Shr;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let shift_bits = self.value_b.lo.expression.clone();
        let divisor_lo = cells.auxiliary_1.expression.clone();
        let divisor_hi = cells.auxiliary_2.expression.clone();
        let reminder_lo = cells.auxiliary_3.expression.clone();
        let reminder_hi = cells.auxiliary_4.expression.clone();

        // TODO: Add overflow constraints.

        // equal to MulAddWordsGadget cells.
        let expr = MulAddWordsOp {
            a_hi: self.value_c.hi.expression.clone(),
            a_lo: self.value_c.lo.expression.clone(),
            b_hi: divisor_hi.clone(),
            b_lo: divisor_lo.clone(),
            c_hi: reminder_hi,
            c_lo: reminder_lo,
            d_hi: self.value_a.hi.expression.clone(),
            d_lo: self.value_a.lo.expression.clone(),
        };
        self.muladd_words_gadget.configure(cb, expr);

        // TODO: reminder < divisor
        // TODO: divisor != 0

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Shr, 0.expr());

        let cond = self.rhs_less_than_128.expr();
        cb.condition(cond.clone(), |cb| {
            cb.add_lookup(
                "pow2 lookups for opcode shl 0",
                Pow2Lookup {
                    pow: shift_bits.clone(),
                    pow_result: divisor_lo,
                },
            );
        });
        cb.condition(1.expr() - cond, |cb| {
            cb.add_lookup(
                "pow2 lookups for opcode shl 1",
                Pow2Lookup {
                    pow: shift_bits - 128u64.expr(),
                    pow_result: divisor_hi,
                },
            );
        });
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

        // b is U8 type data, lower field used.
        let b = get_field_from_op(rw_operations, step.gc + LOWER_FIELD_OFFSET)?.get_lower_32();
        let res = if b < 128 {
            // auxiliary_1 is for lower 128 bit
            let pow2_b_lo = F::from_u128(2).pow(&[b as u64, 0, 0, 0]);
            cells.auxiliary_1.assign(region, offset, Some(pow2_b_lo))?;
            cells.auxiliary_2.assign(region, offset, Some(F::zero()))?;

            let v = decode_field_to_u256(&[F::zero(), pow2_b_lo]);
            Ok(v)
        } else if b < 256 {
            // auxiliary_2 is for upper 128 bit
            let pow2_b_hi = F::from_u128(2).pow(&[(b - 128) as u64, 0, 0, 0]);
            cells.auxiliary_1.assign(region, offset, Some(F::zero()))?;
            cells.auxiliary_2.assign(region, offset, Some(pow2_b_hi))?;
            let v = decode_field_to_u256(&[pow2_b_hi, F::zero()]);
            Ok(v)
        } else {
            error!("rhs value is out of bound");
            Err(Error::Synthesis)
        };
        // rhs less than 128
        self.rhs_less_than_128.assign(
            region,
            offset,
            F::from_u128(b as u128),
            F::from_u128(128u128),
        )?;

        let divident = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let quotient = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let divisor = res.expect("divisor is out of bound");
        let reminder = divident % divisor;
        let rem = convert_u256_to_field::<F>(&reminder);
        cells.auxiliary_3.assign(region, offset, Some(rem[1]))?;
        cells.auxiliary_4.assign(region, offset, Some(rem[0]))?;

        // muladd_gadget assign
        let words = [quotient, divisor, reminder, divident];
        self.muladd_words_gadget.assign(region, offset, words)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let muladd_words_gadget = MulAddWordsGadget::<F>::construct(cb);
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);
        let rhs_less_than_128 = LtGadget::construct(cb, value_b.lo.expression.clone(), 128.expr());

        Self {
            muladd_words_gadget,
            value_a,
            value_b,
            value_c,
            rhs_less_than_128,
        }
    }
}
