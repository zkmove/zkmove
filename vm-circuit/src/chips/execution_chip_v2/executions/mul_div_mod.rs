use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::ConstrainBuilderCommon;
use crate::chips::execution_chip::utils::constraint_builder_v2::{ConstraintBuilderV2, Transition};
use crate::chips::execution_chip_v2::executions::ExecutionState;
use crate::chips::execution_chip_v2::math_gadgets::is_zero::IsZeroGadget;
use crate::chips::execution_chip_v2::math_gadgets::lt::LtGadget;
use crate::chips::execution_chip_v2::math_gadgets::mul_add::MulAddGadget;
use crate::chips::execution_chip_v2::step_v2::{FRAME_INDEX, FUNCTION_INDEX, MODULE_INDEX, PC, SP};
use crate::chips::execution_chip_v2::value::Integer;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::execution_chip_v2::InstructionGadgetV2;
use crate::chips::utilities::Expr;
use gadgets::util::{and, select};
use halo2_proofs::plonk::Expression;
use types::Field;

#[derive(Clone, Debug)]
pub struct MulDivMod<F> {
    is_mul: IsZeroGadget<F>,
    is_div: IsZeroGadget<F>,
    is_mod: IsZeroGadget<F>,
    mul_div_mod: Option<MulDivModGadget<F>>,
}
impl<F: Field> InstructionGadgetV2<F> for MulDivMod<F> {
    const NAME: &'static str = "Mul_Div_Mod";
    const OPCODES: &'static [Opcode] = &[Opcode::Mul, Opcode::Div, Opcode::Mod];
    const EXECUTION_STATE: ExecutionState = ExecutionState::MulDivMod;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self {
        let step_curr = cb.curr.state.clone();
        let step_prev = cb.step_state_at_offset(-1);
        let is_mul =
            IsZeroGadget::construct(cb, (Opcode::Mul as u64).expr() - step_curr.opcode.expr());
        let is_div =
            IsZeroGadget::construct(cb, (Opcode::Div as u64).expr() - step_curr.opcode.expr());
        let is_mod =
            IsZeroGadget::construct(cb, (Opcode::Mod as u64).expr() - step_curr.opcode.expr());
        let mut mul_div_mod = None;

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
            cb.require_state_transition(vec![(SP, Transition::Delta((-1).expr()))]);
        });

        cb.require_equal(
            format!("{}, stack_pop_index(0) == sp(0)", Self::NAME),
            step_curr.stack_pop_index.expr(),
            step_curr.sp.expr(),
        );
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
                format!("{}, stack_push_index(0) == sp(0)", Self::NAME),
                step_curr.stack_push_index.expr(),
                step_curr.sp.expr(),
            );
            cb.require_zero(
                format!("{}, stack_push_sub_index(0) == 0", Self::NAME),
                step_curr.stack_push_sub_index.expr(),
            );

            let lhs = step_curr.stack_pop_value.as_integer();
            let rhs = step_prev.stack_pop_value.as_integer();
            let out = step_curr.stack_push_value.as_integer();
            mul_div_mod = Some(MulDivModGadget::construct(
                cb,
                lhs,
                rhs,
                out,
                is_mul.expr(),
                is_div.expr(),
                is_mod.expr(),
            ));

            cb.require_zero(
                format!("{}, stack_push_value_header(0) == false", Self::NAME),
                step_curr.stack_push_value_header.expr(),
            );
            cb.require_equal(
                format!("{}, stack_push_version(0) == clk(0)", Self::NAME),
                step_curr.stack_push_version.expr(),
                step_curr.clk.expr(),
            );

            cb.require_state_transition(vec![
                (FRAME_INDEX, Transition::Same),
                (MODULE_INDEX, Transition::Same),
                (FUNCTION_INDEX, Transition::Same),
                (SP, Transition::Same),
                (PC, Transition::Delta(1.expr())),
            ]);
        });

        MulDivMod {
            mul_div_mod,
            is_mul,
            is_div,
            is_mod,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MulDivModGadget<F> {
    mul_add: MulAddGadget<F>,
    divisor_is_zero: IsZeroGadget<F>,
    overflow: IsZeroGadget<F>,
    remainder_lt_divisor: LtGadget<F, NUM_OF_BYTES_U256>,
}

impl<F: Field> MulDivModGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilderV2<F>,
        lhs: Integer<F>,
        rhs: Integer<F>,
        out: Integer<F>,
        is_mul: Expression<F>,
        is_div: Expression<F>,
        is_mod: Expression<F>,
    ) -> Self {
        let mul_add = MulAddGadget::construct(cb);
        let mul_add_exprs = mul_add.exprs();
        let a = mul_add_exprs.a_hi.clone() * 2u64.pow(128).expr() + mul_add_exprs.a_lo.clone();
        let b = mul_add_exprs.b_hi.clone() * 2u64.pow(128).expr() + mul_add_exprs.b_lo.clone();
        let c = mul_add_exprs.c_hi.clone() * 2u64.pow(128).expr() + mul_add_exprs.c_lo.clone();
        let d = mul_add_exprs.d_hi.clone() * 2u64.pow(128).expr() + mul_add_exprs.d_lo.clone();

        let divisor_is_zero = IsZeroGadget::construct(cb, b.clone());
        let overflow = IsZeroGadget::construct(cb, mul_add.overflow());
        let remainder_lt_divisor = LtGadget::construct(cb, c.clone(), b.clone());

        // connect "lhs,rhs,out" with "a,b,c,d" according to given opcode
        // lhs == select::expr(is_mul.expr(), a, d);
        // rhs == b;
        // out == is_mul.clone() * d.expr()
        //     + is_div.clone() * a.expr() * (1.expr() - divisor_is_zero.expr())
        //     + is_mod.clone() * c.expr() * (1.expr() - divisor_is_zero.expr());
        //FIXME(?): when is mod and divide by zero, out should be c, but not 0

        cb.require_equal(
            "lhs == select::expr(is_mul.expr(), a, d)",
            lhs.expr(),
            select::expr(is_mul.expr(), a.clone(), d.clone()),
        );
        cb.require_equal("rhs == b", rhs.expr(), b);
        cb.require_equal(
            "constrain out",
            out.expr(),
            is_mul.expr() * d
                + is_div.expr() * a * (1u64.expr() - divisor_is_zero.expr())
                + is_mod.expr() * c.clone() * (1u64.expr() - divisor_is_zero.expr()),
        );

        // for Mul, c must be 0
        cb.require_zero("c == 0 for Mul", c * is_mul.clone());
        // for Div&Mod, remainder < divisor when divisor != 0
        cb.require_true(
            "remainder < divisor when divisor != 0",
            remainder_lt_divisor.expr()
                * (1.expr() - divisor_is_zero.expr())
                * (1.expr() - is_mul.expr()),
        );
        // for Div&Mod, go to Error state if if rhs == 0
        cb.condition(
            and::expr([1.expr() - is_mul.expr(), divisor_is_zero.expr()]),
            |cb| {
                // cb.require_next_state(ExecutionState::ErrorState);
                // ErrorCode == StatusCode::ArithmeticError
            },
        );
        // go to Error state if overflow occurred
        cb.condition(1u64.expr() - overflow.expr(), |_cb| {
            // cb.require_next_state(ExecutionState::ErrorState);
            // ErrorCode == StatusCode::ArithmeticError
        });

        MulDivModGadget {
            mul_add,
            divisor_is_zero,
            overflow,
            remainder_lt_divisor,
        }
    }
}
