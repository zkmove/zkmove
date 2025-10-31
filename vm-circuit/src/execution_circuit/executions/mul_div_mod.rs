use crate::execution_circuit::executions::ExecutionState;
use crate::execution_circuit::step::{StepState, PC, SP};
use crate::execution_circuit::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::execution_circuit::InstructionGadgetV2;
use crate::public_inputs::InstanceTable;
use crate::utils::vm_constraint_builder::{Transition, VmConstraintBuilder};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::Cell;
use field_exts::util::from_bytes;
use field_exts::util::pow_of_two_expr;
use field_exts::util::Expr;
use field_exts::util::{or, select};
use field_exts::Field;
use gadgets::is_zero::IsZero;
use gadgets::is_zero::IsZeroGadget;
use gadgets::lt::LtInteger;
use gadgets::mul_add::MulAddExprs;
use gadgets::mul_add::MulAddGadget;
use gadgets::range_check::IntegerRangeCheck;
use halo2_proofs::{
    circuit::Value,
    plonk::{ErrorFront as Error, Expression},
};
use itertools::izip;
use move_binary_format::file_format_common::Opcodes;
use move_core_types::u256::U256;
use std::marker::PhantomData;
use types::integer::Integer as IntegerExpr;
use types::u256::{pair_u128_to_u256, split_u256_to_u128};
use witness::static_info::StaticInfo;
use witness::step_state::{StageExtraAssignData, StageState};

#[derive(Clone, Debug)]
pub struct MulDivModStage1<F> {
    phantom_data: PhantomData<F>,
}
impl<F: Field> InstructionGadgetV2<F> for MulDivModStage1<F> {
    const NAME: &'static str = "Mul_Div_Mod_Stage1";
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivModStage1;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        cb.first_row(|cb| {
            cb.require_in_set(
                format!("{}, opcode in OPCODES", Self::NAME),
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
            cb.require_equal(
                format!("{}, step_counter(0) == 2", Self::NAME),
                step_curr.step_counter.expr(),
                2u64.expr(),
            );
            cb.require_no_stack_push();
            cb.require_equal(
                format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
                step_curr.stack_pop_index.expr(),
                step_curr.sp.expr(),
            );
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
        //keep sp unchanged to make assign easier
        cb.require_state_transition(vec![(SP, Transition::Same)]);

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
        });

        cb.last_row(|cb| {
            cb.require_next_state(ExecutionState::MulDivModStage2);
            cb.require_state_transition(vec![(PC, Transition::Same)]);
        });

        MulDivModStage1 {
            phantom_data: PhantomData,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        // no need to assign anything else
        Ok(stage_state.rows())
    }
}

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
    bytes_1: [Cell<F>; NUM_OF_BYTES_U128], // used for remainder_lt_divisor
    bytes_2: [Cell<F>; NUM_OF_BYTES_U128], // used for remainder_lt_divisor
}

#[derive(Clone, Debug)]
pub struct MulDivModStage2<F> {
    bytes: [Cell<F>; NUM_OF_BYTES_U128],
    is_mul: IsZeroGadget<F>,
    is_div: IsZeroGadget<F>,
    is_mod: IsZeroGadget<F>,
    mul_div_mod: MulDivModGadget<F>,
    divisor_lo_is_zero: IsZeroGadget<F>,
    divisor_hi_is_zero: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for MulDivModStage2<F> {
    const NAME: &'static str = "Mul_Div_Mod_Stage2";
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivModStage2;

    fn configure(cb: &mut VmConstraintBuilder<F>) -> Self {
        let bytes = cb.query_bytes();

        let mut is_mul = None;
        let mut is_div = None;
        let mut is_mod = None;
        let mut mul_div_mod = None;
        let mut divisor_lo_is_zero = None;
        let mut divisor_hi_is_zero = None;
        let step_curr = cb.curr.state.clone();

        cb.first_row(|cb| {
            cb.require_prev_state(ExecutionState::MulDivModStage1);
            cb.require_equal(
                format!("{}, step_counter(0) == 10", Self::NAME),
                step_curr.step_counter.expr(),
                10u64.expr(),
            );
        });

        cb.require_no_stack_pop();
        cb.require_no_stack_push();
        cb.require_no_local_op();

        cb.last_row(|cb| {
            let step_first_of_stage1 = cb.step_state_at_offset(-11);
            let step_last_of_stage1 = cb.step_state_at_offset(-10);

            let lhs = step_last_of_stage1.stack_pop_value.as_integer();
            let rhs = step_first_of_stage1.stack_pop_value.as_integer();
            let out = step_last_of_stage1.stack_push_value.as_integer();
            let cells = MulDivModCells {
                a_lo: cb.cells_at_offset(bytes.clone(), -9),
                a_hi: cb.cells_at_offset(bytes.clone(), -8),
                b_lo: cb.cells_at_offset(bytes.clone(), -7),
                b_hi: cb.cells_at_offset(bytes.clone(), -6),
                c_lo: cb.cells_at_offset(bytes.clone(), -5),
                c_hi: cb.cells_at_offset(bytes.clone(), -4),
                d_lo: cb.cells_at_offset(bytes.clone(), -3),
                d_hi: cb.cells_at_offset(bytes.clone(), -2),
                bytes_1: cb.cells_at_offset(bytes.clone(), -1),
                bytes_2: bytes.clone(),
            };

            let is_mul_ =
                IsZeroGadget::construct(cb, (Opcodes::MUL as u64).expr() - step_curr.opcode.expr());
            let is_div_ =
                IsZeroGadget::construct(cb, (Opcodes::DIV as u64).expr() - step_curr.opcode.expr());
            let is_mod_ =
                IsZeroGadget::construct(cb, (Opcodes::MOD as u64).expr() - step_curr.opcode.expr());
            let divisor_lo_is_zero_ = IsZeroGadget::construct(cb, rhs.lo());
            let divisor_hi_is_zero_ = IsZeroGadget::construct(cb, rhs.hi());
            let divisor_is_zero = divisor_lo_is_zero_.expr() * divisor_hi_is_zero_.expr();
            let mul_div_mod_ = MulDivModGadget::construct(
                cb,
                cells,
                lhs,
                rhs,
                out,
                is_mul_.expr(),
                is_div_.expr(),
                is_mod_.expr(),
                step_curr.operand0.expr(), //n_bytes
                divisor_is_zero.clone(),
            );

            // for Div&Mod, go to Error state if divisor == 0
            let divide_by_zero = (1u64.expr() - is_mul_.expr()) * divisor_is_zero;
            let overflow = mul_div_mod_.overflow();
            let error = or::expr([divide_by_zero, overflow]);
            cb.condition(error.clone(), |cb| {
                cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });
            cb.condition(1u64.expr() - error, |cb| {
                cb.require_state_transition(vec![
                    (SP, Transition::Delta((-1).expr())),
                    (PC, Transition::Delta(1.expr())),
                ]);
            });
            is_mul = Some(is_mul_);
            is_div = Some(is_div_);
            is_mod = Some(is_mod_);
            divisor_lo_is_zero = Some(divisor_lo_is_zero_);
            divisor_hi_is_zero = Some(divisor_hi_is_zero_);
            mul_div_mod = Some(mul_div_mod_);
        });

        MulDivModStage2 {
            bytes,
            is_mul: is_mul.unwrap(),
            is_div: is_div.unwrap(),
            is_mod: is_mod.unwrap(),
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
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let opcode = step_state.step_state.opcode;
        debug_assert!(
            opcode == Opcodes::MUL as u8
                || opcode == Opcodes::DIV as u8
                || opcode == Opcodes::MOD as u8
        );
        let is_mul = opcode == Opcodes::MUL as u8;
        let is_div = opcode == Opcodes::DIV as u8;
        let is_mod = opcode == Opcodes::MOD as u8;
        let num_bytes = step_state.step_state.operand0 as usize;
        let (lhs, rhs, out) = match &stage_state.extra_data {
            Some(StageExtraAssignData::BinaryOp(d)) => (d.lhs, d.rhs, d.out),
            _ => unreachable!(),
        };
        let (rhs_lo, rhs_hi) = split_u256_to_u128(rhs);
        let (lhs_lo, lhs_hi) = split_u256_to_u128(lhs);
        let (out_lo, out_hi) = split_u256_to_u128(out);

        debug_assert_eq!(step_state.memory_ops.len(), 10);
        self.is_mul.assign(
            region,
            offset + 9,
            F::from(Opcodes::MUL as u64) - F::from(step_state.step_state.opcode as u64),
        )?;
        self.is_div.assign(
            region,
            offset + 9,
            F::from(Opcodes::DIV as u64) - F::from(step_state.step_state.opcode as u64),
        )?;
        self.is_mod.assign(
            region,
            offset + 9,
            F::from(Opcodes::MOD as u64) - F::from(step_state.step_state.opcode as u64),
        )?;
        self.mul_div_mod.assign(
            region,
            offset + 9,
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
            .assign(region, offset + 9, F::from_u128(rhs_lo))?;
        self.divisor_hi_is_zero
            .assign(region, offset + 9, F::from_u128(rhs_hi))?;
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
    range_check: IntegerRangeCheck<F>,
    is_zero: IsZero<F>,
}

impl<F: Field> MulDivModGadget<F> {
    fn construct(
        cb: &mut VmConstraintBuilder<F>,
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

        let a_lo = from_bytes::expr(&cells.a_lo);
        let a_hi = from_bytes::expr(&cells.a_hi);
        let b_lo = from_bytes::expr(&cells.b_lo);
        let b_hi = from_bytes::expr(&cells.b_hi);
        let a = a_hi.clone() * pow_of_two_expr(128) + a_lo.clone();
        let b = b_hi.clone() * pow_of_two_expr(128) + b_lo.clone();

        let c_lo = from_bytes::expr(&cells.c_lo);
        let c_hi = from_bytes::expr(&cells.c_hi);
        let d_lo = from_bytes::expr(&cells.d_lo);
        let d_hi = from_bytes::expr(&cells.d_hi);
        let c = c_hi.clone() * pow_of_two_expr(128) + c_lo.clone();
        let d = d_hi.clone() * pow_of_two_expr(128) + d_lo.clone();

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
            "lhs == select::expr(is_mul.expr(), a, d)".to_string(),
            lhs.expr(),
            select::expr(is_mul.expr(), a.clone(), d.clone()),
        );
        cb.require_equal("rhs == b".to_string(), rhs.expr(), b.clone());
        cb.require_equal(
            "constrain out".to_string(),
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
        cb.require_zero("c == 0 for Mul".to_string(), c.clone() * is_mul.clone());
        let remainder_lt_divisor = LtInteger::construct_from_given_bytes(
            cb,
            c_lo,
            c_hi,
            b_lo,
            b_hi,
            cells.bytes_1.clone(),
            cells.bytes_2.clone(),
        );
        cb.require_zero(
            "remainder < divisor when divisor != 0".to_string(),
            (1u64.expr() - remainder_lt_divisor.expr())
                * (1.expr() - divisor_is_zero.clone())
                * (1.expr() - is_mul.expr()),
        );
        cb.require_zero(
            "for DIV/MOD, overflow == 0".to_string(),
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

        let range_check = IntegerRangeCheck::construct(cb);
        let is_zero = IsZero::construct(cb);
        // when divide by zero, 'out' must be zero, but 'out_lo_bytes' may not be zero
        // we need avoid the conflict
        let not_divide_by_zero = 1u64.expr() - (1u64.expr() - is_mul.expr()) * divisor_is_zero;

        cb.condition(is_u8.expr() * not_divide_by_zero.clone(), |cb| {
            let out_lo_in_range = range_check.expr(cb, out.lo(), NUM_OF_BYTES_U8);
            let out_hi_is_zero = is_zero.expr(cb, out.hi());
            cb.require_equal(
                "!overflow == in_range(out_lo) && is_zero(out_hi)".to_string(),
                1u64.expr() - overflow.expr(),
                out_lo_in_range * out_hi_is_zero,
            );
        });
        cb.condition(is_u16.expr() * not_divide_by_zero.clone(), |cb| {
            let out_lo_in_range = range_check.expr(cb, out.lo(), NUM_OF_BYTES_U16);
            let out_hi_is_zero = is_zero.expr(cb, out.hi());
            cb.require_equal(
                "!overflow == in_range(out_lo) && is_zero(out_hi)".to_string(),
                1u64.expr() - overflow.expr(),
                out_lo_in_range * out_hi_is_zero,
            );
        });
        cb.condition(is_u32.expr() * not_divide_by_zero.clone(), |cb| {
            let out_lo_in_range = range_check.expr(cb, out.lo(), NUM_OF_BYTES_U32);
            let out_hi_is_zero = is_zero.expr(cb, out.hi());
            cb.require_equal(
                "!overflow == in_range(out_lo) && is_zero(out_hi)".to_string(),
                1u64.expr() - overflow.expr(),
                out_lo_in_range * out_hi_is_zero,
            );
        });
        cb.condition(is_u64.expr() * not_divide_by_zero.clone(), |cb| {
            let out_lo_in_range = range_check.expr(cb, out.lo(), NUM_OF_BYTES_U64);
            let out_hi_is_zero = is_zero.expr(cb, out.hi());
            cb.require_equal(
                "!overflow == in_range(out_lo) && is_zero(out_hi)".to_string(),
                1u64.expr() - overflow.expr(),
                out_lo_in_range * out_hi_is_zero,
            );
        });
        cb.condition(is_u128.expr() * not_divide_by_zero.clone(), |cb| {
            let out_lo_in_range = range_check.expr(cb, out.lo(), NUM_OF_BYTES_U128);
            let out_hi_is_zero = is_zero.expr(cb, out.hi());
            cb.require_equal(
                "!overflow == in_range(out_lo) && is_zero(out_hi)".to_string(),
                1u64.expr() - overflow.expr(),
                out_lo_in_range * out_hi_is_zero,
            );
        });

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
            range_check,
            is_zero,
        }
    }

    fn overflow(&self) -> Expression<F> {
        or::expr([self.overflow.expr(), self.mul_add.overflow()])
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

        let (a_lo, a_hi) = split_u256_to_u128(a);
        let (b_lo, b_hi) = split_u256_to_u128(b);
        let (c_lo, c_hi) = split_u256_to_u128(c);
        let (d_lo, d_hi) = split_u256_to_u128(d);

        let cells = [
            self.cells.a_lo.clone(),
            self.cells.a_hi.clone(),
            self.cells.b_lo.clone(),
            self.cells.b_hi.clone(),
            self.cells.c_lo.clone(),
            self.cells.c_hi.clone(),
            self.cells.d_lo.clone(),
            self.cells.d_hi.clone(),
        ]
        .concat();
        let bytes = [
            a_lo.to_le_bytes(),
            a_hi.to_le_bytes(),
            b_lo.to_le_bytes(),
            b_hi.to_le_bytes(),
            c_lo.to_le_bytes(),
            c_hi.to_le_bytes(),
            d_lo.to_le_bytes(),
            d_hi.to_le_bytes(),
        ]
        .concat();

        izip!(cells, bytes)
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.mul_add.assign(region, offset, a, b, c, d)?;

        // assign remainder_lt_divisor
        self.remainder_lt_divisor.assign(region, offset, c, b)?;

        // assign range_check
        let out_lo_in_range = if num_bytes < NUM_OF_BYTES_U256 {
            self.range_check
                .assign(region, offset, F::from_u128(out_lo), num_bytes)?
        } else {
            self.range_check
                .assign(region, offset, F::from_u128(out_lo), NUM_OF_BYTES_U128)?
        };

        // assign is_zero
        self.is_zero.assign(region, offset, F::from_u128(out_hi))?;

        // assign overflow
        let divide_by_zero = (is_div || is_mod) && rhs == U256::zero();
        let overflow = !(divide_by_zero || out_lo_in_range && out_hi == 0);
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

        Ok(())
    }
}
