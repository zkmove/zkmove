use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZero;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtInteger;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddExprs;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::utils::{from_bytes, from_limbs};
use crate::chips::execution_chip_v2::value::Integer as IntegerExpr;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use gadgets::util::{or, select};
use halo2_proofs::plonk::Expression;
use aptos_move_witnesses::step_state::StageState;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use itertools::izip;
use move_core_types::u256::U256;
use move_vm_runtime::witnessing::traced_value::Integer;
use movelang::utility::pair_u128_to_u256;
use types::Field;

#[derive(Clone, Debug)]
struct MulDivModCells<F> {
    a_lo: [Cell<F>; NUM_OF_BYTES_U128],
    a_hi: [Cell<F>; NUM_OF_BYTES_U128],
    b_lo: [Cell<F>; NUM_OF_BYTES_U128],
    b_hi: [Cell<F>; NUM_OF_BYTES_U128],
    c_lo: [Cell<F>; NUM_OF_BYTES_U128],
    c_hi: [Cell<F>; NUM_OF_BYTES_U128],
    d_lo: [Cell<F>; NUM_OF_BYTES_U128],
    d_hi: [Cell<F>; NUM_OF_BYTES_U128],
}

#[derive(Clone, Debug)]
pub struct MulDivMod<F> {
    bytes_1_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_1_hi: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_hi: [Cell<F>; NUM_OF_BYTES_U128],
    is_mul: IsZeroGadget<F>,
    is_div: IsZeroGadget<F>,
    is_mod: IsZeroGadget<F>,
    mul_div_mod: MulDivModGadget<F>,
    divisor_lo_is_zero: IsZeroGadget<F>,
    divisor_hi_is_zero: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for MulDivMod<F> {
    const NAME: &'static str = "Mul_Div_Mod";
    const OPCODE: Opcode = Opcode::Mul; //TODO: remove this
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivMod;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let bytes_1_lo = cb.query_bytes();
        let bytes_1_hi = cb.query_bytes();
        let bytes_2_lo = cb.query_bytes();
        let bytes_2_hi = cb.query_bytes();
        let is_mul =
            IsZeroGadget::construct(cb, (Opcode::Mul as u64).expr() - step_curr.opcode.expr());
        let is_div =
            IsZeroGadget::construct(cb, (Opcode::Div as u64).expr() - step_curr.opcode.expr());
        let is_mod =
            IsZeroGadget::construct(cb, (Opcode::Mod as u64).expr() - step_curr.opcode.expr());
        let mut mul_div_mod = None;
        let mut divisor_lo_is_zero = None;
        let mut divisor_hi_is_zero = None;

        cb.first_row(|cb| {
            cb.require_equal(
                "step_counter(0) == 2",
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
            //keep sp unchanged to make assign easier
            cb.require_state_transition(vec![(SP, Transition::Same)]);
        });

        cb.require_zero(
            format!("{}, stack_pop_sub_index(0) == 0", Self::NAME),
            step_curr.stack_pop_sub_index.expr(),
        );
        cb.require_zero(
            format!("{}, stack_pop_value_header(0) == false", Self::NAME),
            step_curr.stack_pop_value_header.expr(),
        );
        cb.require_no_local_op();

        cb.last_row(|cb| {
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_index(0) == sp(0) - 1", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr() - 1u64.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();
            let cells = MulDivModCells {
                a_lo: cb.cells_at_offset(bytes_1_lo.clone(), -1),
                a_hi: cb.cells_at_offset(bytes_1_hi.clone(), -1),
                b_lo: cb.cells_at_offset(bytes_2_lo.clone(), -1),
                b_hi: cb.cells_at_offset(bytes_2_hi.clone(), -1),
                c_lo: bytes_1_lo.clone(),
                c_hi: bytes_1_hi.clone(),
                d_lo: bytes_2_lo.clone(),
                d_hi: bytes_2_hi.clone(),
            };

            let divisor_lo_is_zero_ = IsZeroGadget::construct(cb, rhs.lo());
            let divisor_hi_is_zero_ = IsZeroGadget::construct(cb, rhs.hi());
            let divisor_is_zero = divisor_lo_is_zero_.expr() * divisor_hi_is_zero_.expr();
            let mul_div_mod_ = MulDivModGadget::construct(
                cb,
                cells,
                lhs,
                rhs,
                out,
                is_mul.expr(),
                is_div.expr(),
                is_mod.expr(),
                step_curr.aux0.expr(), //n_bytes
                divisor_is_zero.clone(),
            );

            // for Div&Mod, go to Error state if divisor == 0
            let divide_by_zero = (1u64.expr() - is_mul.expr()) * divisor_is_zero;
            let overflow = mul_div_mod_.overflow();
            let error = or::expr([divide_by_zero, overflow]);
            cb.condition(error.clone(), |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
            cb.condition(1u64.expr() - error, |cb| {
                cb.require_state_transition(vec![
                    (FRAME_INDEX, Transition::Same),
                    (MODULE_INDEX, Transition::Same),
                    (FUNCTION_INDEX, Transition::Same),
                    (SP, Transition::Delta((-1).expr())),
                    (PC, Transition::Delta(1.expr())),
                ]);
            });
            divisor_lo_is_zero = Some(divisor_lo_is_zero_);
            divisor_hi_is_zero = Some(divisor_hi_is_zero_);
            mul_div_mod = Some(mul_div_mod_);
        });

        MulDivMod {
            bytes_1_lo,
            bytes_1_hi,
            bytes_2_lo,
            bytes_2_hi,
            is_mul,
            is_div,
            is_mod,
            mul_div_mod: mul_div_mod.unwrap(),
            divisor_lo_is_zero: divisor_lo_is_zero.unwrap(),
            divisor_hi_is_zero: divisor_hi_is_zero.unwrap(),
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let opcode = step_state.step_state.opcode;
        debug_assert!(
            opcode == Opcode::Mul as u16
                || opcode == Opcode::Div as u16
                || opcode == Opcode::Mod as u16
        );
        let is_mul = if opcode == Opcode::Mul as u16 {
            true
        } else {
            false
        };
        let is_div = if opcode == Opcode::Div as u16 {
            true
        } else {
            false
        };
        let is_mod = if opcode == Opcode::Mod as u16 {
            true
        } else {
            false
        };

        let num_bytes = step_state.step_state.aux0 as usize;
        let rhs = step_state.memory_ops[0].0.clone().unwrap().value;
        let lhs = step_state.memory_ops[1].0.clone().unwrap().value;
        let out = step_state.memory_ops[1].1.clone().unwrap().value;
        let (rhs_lo, rhs_hi) = Integer::try_from(rhs).unwrap().into();
        let (lhs_lo, lhs_hi) = Integer::try_from(lhs).unwrap().into();
        let (out_lo, out_hi) = Integer::try_from(out).unwrap().into();

        debug_assert_eq!(step_state.memory_ops.len(), 2);
        for i in 0..step_state.memory_ops.len() {
            self.is_mul.assign(
                region,
                offset + i,
                F::from(step_state.step_state.opcode as u64) - F::from(Opcode::Mul as u64),
            )?;
            self.is_div.assign(
                region,
                offset + i,
                F::from(step_state.step_state.opcode as u64) - F::from(Opcode::Div as u64),
            )?;
            self.is_mod.assign(
                region,
                offset + i,
                F::from(step_state.step_state.opcode as u64) - F::from(Opcode::Mod as u64),
            )?;
        }

        self.mul_div_mod.assign(
            region,
            offset + 1,
            is_mul,
            is_div,
            is_mod,
            num_bytes,
            lhs_lo,
            lhs_hi,
            rhs_lo,
            rhs_hi,
            out_lo,
            out_hi,
        )?;

        self.divisor_lo_is_zero
            .assign(region, offset + 1, F::from_u128(rhs_lo))?;
        self.divisor_hi_is_zero
            .assign(region, offset + 1, F::from_u128(rhs_hi))?;
        Ok(step_state.memory_ops.len())
    }
}

#[derive(Clone, Debug)]
struct MulDivModGadget<F> {
    cells: MulDivModCells<F>,
    mul_add: MulAddGadget<F>,
    remainder_lt_divisor: LtInteger<F>,
    overflow: Cell<F>,
    is_u8: IsZeroGadget<F>,
    is_u16: IsZeroGadget<F>,
    is_u32: IsZeroGadget<F>,
    is_u64: IsZeroGadget<F>,
    is_u128: IsZeroGadget<F>,
    is_out_lo_in_range: IsZero<F>,
    is_zero_out_hi: IsZero<F>,
}

impl<F: Field> MulDivModGadget<F> {
    fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        cells: MulDivModCells<F>,
        lhs: IntegerExpr<F>,
        rhs: IntegerExpr<F>,
        out: IntegerExpr<F>,
        is_mul: Expression<F>,
        is_div: Expression<F>,
        is_mod: Expression<F>,
        n_bytes: Expression<F>,
        divisor_is_zero: Expression<F>,
    ) -> Self {
        let a_limbs = [
            from_bytes::expr(&cells.a_lo[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.a_lo[NUM_OF_BYTES_U64..]),
            from_bytes::expr(&cells.a_hi[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.a_hi[NUM_OF_BYTES_U64..]),
        ];
        let b_limbs = [
            from_bytes::expr(&cells.b_lo[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.b_lo[NUM_OF_BYTES_U64..]),
            from_bytes::expr(&cells.b_hi[..NUM_OF_BYTES_U64]),
            from_bytes::expr(&cells.b_hi[NUM_OF_BYTES_U64..]),
        ];
        let a = from_limbs::expr::<_, _, 64>(&a_limbs);
        let b = from_limbs::expr::<_, _, 64>(&b_limbs);
        let b_lo = from_bytes::expr(&cells.b_lo);
        let b_hi = from_bytes::expr(&cells.b_hi);

        let c_lo = from_bytes::expr(&cells.c_lo);
        let c_hi = from_bytes::expr(&cells.c_hi);
        let d_lo = from_bytes::expr(&cells.d_lo);
        let d_hi = from_bytes::expr(&cells.d_hi);
        let c = c_hi.clone() * 2u64.pow(128).expr() + c_lo.clone();
        let d = d_hi.clone() * 2u64.pow(128).expr() + d_lo.clone();

        let overflow = cb.query_bool();

        // Connect "lhs,rhs,out" with "a,b,c,d":
        //
        // lhs == select::expr(is_mul.expr(), a, d);
        // rhs == b;
        // out == is_mul.clone() * d.expr()
        //     + is_div.clone() * a.expr() * (1.expr() - divisor_is_zero)
        //     + is_mod.clone() * c.expr() * (1.expr() - divisor_is_zero);

        //Notice: when is_mod or is_div, and divide by zero, 'out' is constrained to be 0.
        cb.require_equal(
            "lhs == select::expr(is_mul.expr(), a, d)",
            lhs.expr(),
            select::expr(is_mul.expr(), a.clone(), d.clone()),
        );
        cb.require_equal("rhs == b", rhs.expr(), b.clone());
        cb.require_equal(
            "constrain out",
            out.expr(),
            is_mul.expr() * d
                + is_div.expr() * a * (1u64.expr() - divisor_is_zero.clone())
                + is_mod.expr() * c.clone() * (1u64.expr() - divisor_is_zero.clone()),
        );

        // Construct MulAddGadget
        let mul_add_exprs = MulAddExprs {
            a_limbs,
            b_limbs,
            c_hi: c_hi.clone(),
            c_lo: c_lo.clone(),
            d_hi,
            d_lo,
        };
        let mul_add = MulAddGadget::construct(cb, &mul_add_exprs);

        // Constraints for a, b, c, d:
        //
        // for Mul, c must be 0
        // for Div&Mod, remainder(c) < divisor(b) when divisor != 0
        // for Div&Mod, overflow == 0
        cb.require_zero("c == 0 for Mul", c.clone() * is_mul.clone());
        let remainder_lt_divisor = LtInteger::construct(cb, c_lo, c_hi, b_lo, b_hi);
        cb.require_zero(
            "remainder < divisor when divisor != 0",
            (1u64.expr() - remainder_lt_divisor.expr())
                * (1.expr() - divisor_is_zero.clone())
                * (1.expr() - is_mul.expr()),
        );
        cb.require_zero(
            "for DIV/MOD, overflow == 0",
            mul_add.overflow() * (1.expr() - is_mul.expr()),
        );

        // Handle overflow
        //
        // overflow check on the output according to the operand type. We don't need check
        // U256, it's already covered by overflow check for MulAddGadget
        let is_u8 = IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr());
        let is_u16 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr());
        let is_u32 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr());
        let is_u64 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr());
        let is_u128 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U128 as u64).expr());
        let is_out_lo_in_range = IsZero::construct(cb);
        let out_lo_bytes = izip!(&cells.d_lo, &cells.a_lo, &cells.c_lo)
            .map(|(c1, c2, c3)| {
                is_mul.expr() * c1.expr() + is_div.expr() * c2.expr() + is_mod.expr() * c3.expr()
            })
            .collect::<Vec<_>>();

        let is_out_lo_in_range_u8 = is_out_lo_in_range.expr(
            cb,
            out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U8]),
        );
        let is_out_lo_in_range_u16 = is_out_lo_in_range.expr(
            cb,
            out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U16]),
        );
        let is_out_lo_in_range_u32 = is_out_lo_in_range.expr(
            cb,
            out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U32]),
        );
        let is_out_lo_in_range_u64 = is_out_lo_in_range.expr(
            cb,
            out.lo() - from_bytes::expr(&out_lo_bytes[..NUM_OF_BYTES_U64]),
        );
        let is_out_lo_in_range_u128 =
            is_out_lo_in_range.expr(cb, out.lo() - from_bytes::expr(&out_lo_bytes));

        let overflow_out_lo = is_u8.expr() * (1u64.expr() - is_out_lo_in_range_u8)
            + is_u16.expr() * (1u64.expr() - is_out_lo_in_range_u16)
            + is_u32.expr() * (1u64.expr() - is_out_lo_in_range_u32)
            + is_u64.expr() * (1u64.expr() - is_out_lo_in_range_u64)
            + is_u128.expr() * (1u64.expr() - is_out_lo_in_range_u128);

        // when divide by zero, 'out' must be zero, but 'out_lo_bytes' may not be zero
        // we need avoid the conflict
        let divide_by_zero = (1u64.expr() - is_mul.expr()) * divisor_is_zero;
        let overflow_out_lo = (1u64.expr() - divide_by_zero) * overflow_out_lo;

        let is_zero_out_hi = IsZero::construct(cb);
        let out_hi_not_zero =
            (is_u8.expr() + is_u16.expr() + is_u32.expr() + is_u64.expr() + is_u128.expr())
                * (1u64.expr() - is_zero_out_hi.expr(cb, out.hi()));

        cb.require_equal(
            "overflow",
            overflow.expr(),
            or::expr([mul_add.overflow(), overflow_out_lo, out_hi_not_zero]),
        );

        MulDivModGadget {
            cells,
            mul_add,
            remainder_lt_divisor,
            overflow,
            is_u8,
            is_u16,
            is_u32,
            is_u64,
            is_u128,
            is_out_lo_in_range,
            is_zero_out_hi,
        }
    }

    fn overflow(&self) -> Expression<F> {
        self.overflow.expr()
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        is_mul: bool,
        is_div: bool,
        is_mod: bool,
        num_bytes: usize,
        lhs_lo: u128,
        lhs_hi: u128,
        rhs_lo: u128,
        rhs_hi: u128,
        out_lo: u128,
        out_hi: u128,
    ) -> Result<(), Error> {
        let lhs = pair_u128_to_u256(lhs_lo, lhs_hi);
        let rhs = pair_u128_to_u256(rhs_lo, rhs_hi);
        let out = pair_u128_to_u256(out_lo, out_hi);
        let (a, b, c, d) = if is_mul {
            (lhs, rhs, U256::zero(), out)
        } else if is_div {
            (out, rhs, lhs - out * rhs, lhs)
        } else {
            (
                if rhs == U256::zero() {
                    U256::zero()
                } else {
                    lhs / rhs
                },
                rhs,
                if rhs == U256::zero() { lhs } else { out },
                lhs,
            )
        };

        let mul_add_overflow = self.mul_add.assign(region, offset, a, b, c, d)?;

        // assign remainder_lt_divisor
        self.remainder_lt_divisor
            .assign(region, offset, Integer::U256(c), Integer::U256(b))?;

        // assign is_out_lo_in_range
        let out_lo_bytes = out_lo.to_le_bytes();
        let out_lo_expected = match num_bytes {
            NUM_OF_BYTES_U8 => u8::from_le_bytes(out_lo_bytes[..1].try_into().unwrap()) as u128,
            NUM_OF_BYTES_U16 => u16::from_le_bytes(out_lo_bytes[..2].try_into().unwrap()) as u128,
            NUM_OF_BYTES_U32 => u32::from_le_bytes(out_lo_bytes[..4].try_into().unwrap()) as u128,
            NUM_OF_BYTES_U64 => u64::from_le_bytes(out_lo_bytes[..8].try_into().unwrap()) as u128,
            NUM_OF_BYTES_U128 => u128::from_le_bytes(out_lo_bytes.try_into().unwrap()) as u128,
            NUM_OF_BYTES_U256 => u128::from_le_bytes(out_lo_bytes.try_into().unwrap()) as u128,
            _ => unreachable!(),
        };
        self.is_out_lo_in_range.assign(
            region,
            offset,
            F::from_u128(out_lo) - F::from_u128(out_lo_expected),
        )?;

        // assign overflow
        let divide_by_zero = (is_div || is_mod) && rhs == U256::zero();
        let out_lo_not_in_range = match num_bytes {
            NUM_OF_BYTES_U8 => out_lo > u8::MAX as u128,
            NUM_OF_BYTES_U16 => out_lo > u16::MAX as u128,
            NUM_OF_BYTES_U32 => out_lo > u32::MAX as u128,
            NUM_OF_BYTES_U64 => out_lo > u64::MAX as u128,
            NUM_OF_BYTES_U128 => out_lo > u128::MAX as u128,
            NUM_OF_BYTES_U256 => out_lo > u128::MAX as u128,
            _ => unreachable!(),
        };
        let overflow_out_lo = !divide_by_zero && out_lo_not_in_range;
        let overflow = mul_add_overflow || overflow_out_lo || out_hi != 0;
        self.overflow.assign(
            region,
            offset,
            Value::known(if overflow { F::one() } else { F::zero() }),
        )?;

        self.is_u8.assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U8 as u64),
        )?;
        self.is_u16.assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U16 as u64),
        )?;
        self.is_u32.assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U32 as u64),
        )?;
        self.is_u64.assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U64 as u64),
        )?;
        self.is_u128.assign(
            region,
            offset,
            F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U128 as u64),
        )?;

        self.is_zero_out_hi
            .assign(region, offset, F::from_u128(out_hi))?;

        Ok(())
    }
}
