use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::lookup_table::Lookup;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::{LtGadget, LtInteger};
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddExprs;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddGadget;
use crate::chips::execution_chip_v2::step_v2::{
    StepState, FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP,
};
use crate::chips::execution_chip_v2::utils::{from_bytes, pow_of_two_expr};
use crate::chips::execution_chip_v2::value::Integer as IntegerExpr;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::Cell;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::select;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use itertools::izip;
use move_core_types::u256::U256;
use movelang::utility::{pair_u128_to_u256, split_u256_to_u128};
use types::Field;

#[derive(Clone, Debug)]
struct ShiftCells<F> {
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
pub struct Shift<F> {
    bytes_1_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_1_hi: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_lo: [Cell<F>; NUM_OF_BYTES_U128],
    bytes_2_hi: [Cell<F>; NUM_OF_BYTES_U128],
    is_shl: IsZeroGadget<F>,
    shift_gadget: ShiftGadget<F>,
    rhs_lt256: LtGadget<F, NUM_OF_BYTES_U8>,
    rhs_lt128: LtGadget<F, NUM_OF_BYTES_U8>,
    rhs_lt64: LtGadget<F, NUM_OF_BYTES_U8>,
    rhs_lt32: LtGadget<F, NUM_OF_BYTES_U8>,
    rhs_lt16: LtGadget<F, NUM_OF_BYTES_U8>,
    rhs_lt8: LtGadget<F, NUM_OF_BYTES_U8>,
    is_u8: IsZeroGadget<F>,
    is_u16: IsZeroGadget<F>,
    is_u32: IsZeroGadget<F>,
    is_u64: IsZeroGadget<F>,
    is_u128: IsZeroGadget<F>,
    is_u256: IsZeroGadget<F>,
}
impl<F: Field> InstructionGadgetV2<F> for Shift<F> {
    const NAME: &'static str = "Shift";
    const EXECUTION_STATE: ExecutionState = ExecutionState::Shift;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let bytes_1_lo = cb.query_bytes();
        let bytes_1_hi = cb.query_bytes();
        let bytes_2_lo = cb.query_bytes();
        let bytes_2_hi = cb.query_bytes();
        let is_shl =
            IsZeroGadget::construct(cb, (Opcode::Shl as u64).expr() - step_curr.opcode.expr());
        let mut shift_gadget = None;
        let mut rhs_lt256 = None;
        let mut rhs_lt128 = None;
        let mut rhs_lt64 = None;
        let mut rhs_lt32 = None;
        let mut rhs_lt16 = None;
        let mut rhs_lt8 = None;

        let n_bytes = step_curr.aux0.expr();
        let is_u8 = IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr());
        let is_u16 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr());
        let is_u32 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr());
        let is_u64 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr());
        let is_u128 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U128 as u64).expr());
        let is_u256 =
            IsZeroGadget::construct(cb, n_bytes.clone() - (NUM_OF_BYTES_U256 as u64).expr());
        cb.first_row(|cb| {
            cb.require_in_set(
                "opcode in OPCODES",
                step_curr.opcode.expr(),
                Self::OPCODES.iter().map(|v| (*v as u64).expr()).collect(),
            );
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
                "stack_push_version(0) == clk(0)",
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();

            let rhs_lt_256 = LtGadget::construct(cb, rhs.expr(), 256u64.expr());
            let rhs_lt_128 = LtGadget::construct(cb, rhs.expr(), 128u64.expr());
            let rhs_lt_64 = LtGadget::construct(cb, rhs.expr(), 64u64.expr());
            let rhs_lt_32 = LtGadget::construct(cb, rhs.expr(), 32u64.expr());
            let rhs_lt_16 = LtGadget::construct(cb, rhs.expr(), 16u64.expr());
            let rhs_lt_8 = LtGadget::construct(cb, rhs.expr(), 8u64.expr());

            // Opcode Shl and Shr shifts the "lhs" integer "rhs" bits and pushes the "out" on the stack.
            // lhs and out can be U8, U16, U32, U64, U128 or U256
            // rhs can only be U8
            cb.require_true(format!("{}, rhs < 256", Self::NAME), rhs_lt_256.expr());

            // According to VM implementation, if lhs has integer type UX, rhs must be less then N_BITS_UX,
            // otherwise goto Error
            let error = is_u8.expr() * (1u64.expr() - rhs_lt_8.expr())
                + is_u16.expr() * (1u64.expr() - rhs_lt_16.expr())
                + is_u32.expr() * (1u64.expr() - rhs_lt_32.expr())
                + is_u64.expr() * (1u64.expr() - rhs_lt_64.expr())
                + is_u128.expr() * (1u64.expr() - rhs_lt_128.expr());
            cb.condition(error, |_cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            });

            let cells = ShiftCells {
                a_lo: cb.cells_at_offset(bytes_1_lo.clone(), -1),
                a_hi: cb.cells_at_offset(bytes_1_hi.clone(), -1),
                b_lo: cb.cells_at_offset(bytes_2_lo.clone(), -1),
                b_hi: cb.cells_at_offset(bytes_2_hi.clone(), -1),
                c_lo: bytes_1_lo.clone(),
                c_hi: bytes_1_hi.clone(),
                d_lo: bytes_2_lo.clone(),
                d_hi: bytes_2_hi.clone(),
            };

            let shift = ShiftGadget::construct(
                cb,
                cells,
                lhs,
                rhs,
                out,
                is_shl.expr(),
                is_u8.expr(),
                is_u16.expr(),
                is_u32.expr(),
                is_u64.expr(),
                is_u128.expr(),
                is_u256.expr(),
            );

            rhs_lt256 = Some(rhs_lt_256);
            rhs_lt128 = Some(rhs_lt_128);
            rhs_lt64 = Some(rhs_lt_64);
            rhs_lt32 = Some(rhs_lt_32);
            rhs_lt16 = Some(rhs_lt_16);
            rhs_lt8 = Some(rhs_lt_8);
            shift_gadget = Some(shift);

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Delta((-1).expr())),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        Shift {
            bytes_1_lo,
            bytes_1_hi,
            bytes_2_lo,
            bytes_2_hi,
            is_shl,
            shift_gadget: shift_gadget.unwrap(),
            rhs_lt256: rhs_lt256.unwrap(),
            rhs_lt128: rhs_lt128.unwrap(),
            rhs_lt64: rhs_lt64.unwrap(),
            rhs_lt32: rhs_lt32.unwrap(),
            rhs_lt16: rhs_lt16.unwrap(),
            rhs_lt8: rhs_lt8.unwrap(),
            is_u8,
            is_u16,
            is_u32,
            is_u64,
            is_u128,
            is_u256,
        }
    }

    fn assign(
        &self,
        _step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());
        let step_state = stage_state.step_states.first().unwrap();
        let opcode = step_state.step_state.opcode;
        debug_assert!(opcode == Opcode::Shl as u8 || opcode == Opcode::Shr as u8);
        let is_shl = opcode == Opcode::Shl as u8;
        let num_bytes = step_state.step_state.aux0 as usize;
        let pop0 = step_state.memory_ops[0].0.clone().unwrap().value;
        let rhs = pop0.to_u8_unchecked();
        let lhs = step_state.memory_ops[1].0.clone().unwrap().value;
        let out = step_state.memory_ops[1].1.clone().unwrap().value;
        let lhs_lo = lhs.lo();
        let lhs_hi = lhs.hi();
        let out_lo = out.lo();
        let out_hi = out.hi();

        debug_assert_eq!(step_state.memory_ops.len(), 2);
        for i in 0..step_state.memory_ops.len() {
            self.is_shl.assign(
                region,
                offset + i,
                F::from(Opcode::Shl as u64) - F::from(step_state.step_state.opcode as u64),
            )?;
            self.is_u8.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U8 as u64),
            )?;
            self.is_u16.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U16 as u64),
            )?;
            self.is_u32.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U32 as u64),
            )?;
            self.is_u64.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U64 as u64),
            )?;
            self.is_u128.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U128 as u64),
            )?;
            self.is_u256.assign(
                region,
                offset + i,
                F::from(num_bytes as u64) - F::from(NUM_OF_BYTES_U256 as u64),
            )?;
        }

        //for below gadget, we only assign the last row
        self.shift_gadget.assign(
            region,
            offset + 1,
            is_shl,
            rhs,
            lhs_lo,
            lhs_hi,
            out_lo,
            out_hi,
        )?;
        self.rhs_lt256
            .assign(region, offset + 1, F::from(rhs as u64), F::from(256u64))?;
        self.rhs_lt128
            .assign(region, offset + 1, F::from(rhs as u64), F::from(128u64))?;
        self.rhs_lt64
            .assign(region, offset + 1, F::from(rhs as u64), F::from(64u64))?;
        self.rhs_lt32
            .assign(region, offset + 1, F::from(rhs as u64), F::from(32u64))?;
        self.rhs_lt16
            .assign(region, offset + 1, F::from(rhs as u64), F::from(16u64))?;
        self.rhs_lt8
            .assign(region, offset + 1, F::from(rhs as u64), F::from(8u64))?;

        Ok(step_state.memory_ops.len())
    }
}

#[derive(Clone, Debug)]
struct ShiftGadget<F> {
    cells: ShiftCells<F>,
    mul_add: MulAddGadget<F>,
    remainder_lt_divisor: LtInteger<F>,
}

impl<F: Field> ShiftGadget<F> {
    fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        cells: ShiftCells<F>,
        lhs: IntegerExpr<F>,
        rhs: IntegerExpr<F>,
        out: IntegerExpr<F>,
        is_shl: Expression<F>,
        is_u8: Expression<F>,
        is_u16: Expression<F>,
        is_u32: Expression<F>,
        is_u64: Expression<F>,
        is_u128: Expression<F>,
        is_u256: Expression<F>,
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
        let a = a_hi.clone() * pow_of_two_expr(128) + a_lo.clone();

        let b_lo = from_bytes::expr(&cells.b_lo);
        let b_hi = from_bytes::expr(&cells.b_hi);

        let c_lo = from_bytes::expr(&cells.c_lo);
        let c_hi = from_bytes::expr(&cells.c_hi);
        let d_lo = from_bytes::expr(&cells.d_lo);
        let d_hi = from_bytes::expr(&cells.d_hi);
        let c = c_hi.clone() * pow_of_two_expr(128) + c_lo.clone();
        let d = d_hi.clone() * pow_of_two_expr(128) + d_lo.clone();

        // Connect "lhs,rhs,out" with "a,b,c,d":
        //
        // lhs == select(is_shl, a, d);
        // 2^rhs == b; (b != 0, because rhs < 256)
        // out == is_shl * from_bytes(d[..n_bytes]) + is_shr * a;
        //
        let is_shr = 1u64.expr() - is_shl.expr();
        cb.require_equal(
            "lhs == select::expr(is_shl.expr(), a, d)",
            lhs.expr(),
            select::expr(is_shl.expr(), a.clone(), d.clone()),
        );
        // (b_lo, b_hi) == (2^rhs, 0), when rhs < 128
        // (b_lo, b_hi) == (0, 2^(rhs - 128)), when rhs >= 128
        cb.add_lookup(
            "2^rhs == b",
            Lookup::Pow2 {
                value: rhs.expr(),
                pow_lo: b_lo.clone(),
                pow_hi: b_hi.clone(),
            },
        );
        cb.require_equal(
            "constrain out shl",
            out.expr(),
            is_shr.clone() * a
                + is_shl.clone() * is_u8 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U8])
                + is_shl.clone() * is_u16 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U16])
                + is_shl.clone() * is_u32 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U32])
                + is_shl.clone() * is_u64 * from_bytes::expr(&cells.d_lo[..NUM_OF_BYTES_U64])
                + is_shl.clone() * is_u128 * d_lo.clone()
                + is_shl.clone() * is_u256 * d,
        );

        // Constraints for a, b, c, d:
        //
        // for shl, c must be 0, mul_add could overflow, it doesn't impact shift result
        // for shr, c < b (remainder < divisor, shl also applicable), mul_add never overflow
        //
        cb.require_zero("c == 0 for shl", c.clone() * is_shl.clone());
        let remainder_lt_divisor = LtInteger::construct(cb, c_lo.clone(), c_hi.clone(), b_lo, b_hi);
        cb.require_true("remainder < divisor", remainder_lt_divisor.expr());
        let mul_add_exprs = MulAddExprs {
            a_limbs,
            b_limbs,
            c_hi,
            c_lo,
            d_hi,
            d_lo,
        };
        let mul_add = MulAddGadget::construct(cb, &mul_add_exprs);
        cb.require_zero(
            "overflow == 0 for opcode shr",
            is_shr.clone() * mul_add.overflow(),
        );

        ShiftGadget {
            cells,
            mul_add,
            remainder_lt_divisor,
        }
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        is_shl: bool,
        rhs: u8,
        lhs_lo: u128,
        lhs_hi: u128,
        out_lo: u128,
        out_hi: u128,
    ) -> Result<(), Error> {
        let lhs = pair_u128_to_u256(lhs_lo, lhs_hi);
        let out = pair_u128_to_u256(out_lo, out_hi);

        // (b_lo, b_hi) == (2^rhs, 0), when rhs < 128
        // (b_lo, b_hi) == (0, 2^(rhs - 128)), when rhs >= 128
        let (b_lo, b_hi) = if rhs < 128 {
            (1u128 << rhs, 0u128)
        } else {
            (0u128, 1u128 << (rhs - 128))
        };
        let b = pair_u128_to_u256(b_lo, b_hi);

        let (a, c, d) = if is_shl {
            (lhs, U256::zero(), out)
        } else {
            (out, lhs - out * b, lhs)
        };

        let (a_lo, a_hi) = split_u256_to_u128(a);
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

        Ok(())
    }
}
