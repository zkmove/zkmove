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
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use move_core_types::u256::U256;
use movelang::utility::decode_field_to_u256;
use movelang::value_ext::{LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET};
use types::Field;

use super::common::word_gadget::WordCells;
use super::common::{get_field_from_op, get_u256_from_op};

#[derive(Clone, Debug)]
pub struct Shl<F: Field> {
    muladd_words_gadget: MulAddWordsGadget<F>,
    value_a: WordCells<F>,
    value_b: WordCells<F>,
    value_c: WordCells<F>,
    rhs_less_than_128: LtGadget<F, 1>,
}

impl<F: Field> InstructionGadget<F> for Shl<F> {
    const NAME: &'static str = "SHL";

    const OPCODE: Opcode = Opcode::Shl;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for rhs is u8, only lower field is taken care.
        let rhs = self.value_b.lo.expression.clone();
        let divisor_hi = cells.auxiliary_2.expression.clone();
        let divisor_lo = cells.auxiliary_1.expression.clone();

        // TODO: should we constraint that rhs is in u8 range?
        // TODO: Add overflow constraints.

        // equal to MulAddWordsGadget cells.
        let expr = MulAddWordsOp {
            a_hi: self.value_a.hi.expression.clone(),
            a_lo: self.value_a.lo.expression.clone(),
            b_hi: divisor_hi.clone(),
            b_lo: divisor_lo.clone(),
            c_hi: 0u64.expr(),
            c_lo: 0u64.expr(),
            d_hi: self.value_c.hi.expression.clone(),
            d_lo: self.value_c.lo.expression.clone(),
        };
        self.muladd_words_gadget.configure(cb, expr);

        let binary_op = BinaryOp {
            value_a: self.value_a.clone(),
            value_b: self.value_b.clone(),
            value_c: self.value_c.clone(),
        };
        BinaryOp::constrain_binary_op(cb, cells);
        BinaryOp::lookup_binary_op(cb, cells, &binary_op);
        LookupBytecode::lookup_bytecode(cb, cells, Opcode::Shl, 0u64.expr());
        let cond = self.rhs_less_than_128.expr();
        cb.condition(cond.clone(), |cb| {
            cb.add_lookup(
                "pow2 lookups for opcode shl 0",
                Pow2Lookup {
                    pow: rhs.clone(),
                    pow_result: divisor_lo,
                },
            );
        });
        cb.condition(1u64.expr() - cond, |cb| {
            cb.add_lookup(
                "pow2 lookups for opcode shl 1",
                Pow2Lookup {
                    pow: rhs - 128u64.expr(),
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
            let pow2_b_lo = F::from_u128(2).pow([b as u64, 0, 0, 0]);
            cells.auxiliary_1.assign(region, offset, Some(pow2_b_lo))?;
            cells.auxiliary_2.assign(region, offset, Some(F::ZERO))?;

            let v = decode_field_to_u256(&[F::ZERO, pow2_b_lo]);
            Ok(v)
        } else if b < 256 {
            // auxiliary_2 is for upper 128 bit
            let pow2_b_hi = F::from_u128(2).pow([(b - 128) as u64, 0, 0, 0]);
            cells.auxiliary_1.assign(region, offset, Some(F::ZERO))?;
            cells.auxiliary_2.assign(region, offset, Some(pow2_b_hi))?;
            let v = decode_field_to_u256(&[pow2_b_hi, F::ZERO]);
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

        // muladd_gadget assign
        let quotient = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let divident = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let divisor = res.expect("divisor is out of bound");
        let words = [quotient, divisor, U256::zero(), divident];
        self.muladd_words_gadget.assign(region, offset, words)?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let muladd_words_gadget = MulAddWordsGadget::<F>::construct(cb);
        let value_a = WordCells::<F>::construct(cb);
        let value_b = WordCells::<F>::construct(cb);
        let value_c = WordCells::<F>::construct(cb);
        let rhs_less_than_128 =
            LtGadget::construct(cb, value_b.lo.expression.clone(), 128u64.expr());

        Self {
            muladd_words_gadget,
            value_a,
            value_b,
            value_c,
            rhs_less_than_128,
        }
    }
}
