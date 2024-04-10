use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::STEP_CHIP_WIDTH;
use crate::chips::execution_chip::step_v2::Step;
use crate::chips::execution_chip::utils::base_constraint_builder::BaseConstraintBuilder;
use crate::chips::utilities::Expr;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, FirstPhase, Selector};
use std::iter;
use types::Field;

#[derive(Clone)]
pub struct ExecChipConfig<F> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub advices: [Column<Advice>; STEP_CHIP_WIDTH],
    pub step: Step<F>,
}

impl<F: Field> ExecChipConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let s_usable = meta.complex_selector();
        let s_step_first = meta.complex_selector();
        let s_step_last = meta.complex_selector();
        let advices: [Column<Advice>; STEP_CHIP_WIDTH] = [(); STEP_CHIP_WIDTH]
            .iter()
            .enumerate()
            .map(|(n, _)| meta.advice_column_in(FirstPhase))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let cur_step = Step::new(meta, advices, 0);
        let prev_step = Step::new(meta, advices, -1);
        meta.create_gate("s_step_first", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(s_step_first.clone(), |cb| {
                cb.require_zero("first step, pc = 0", cur_step.state.clk.expr());
                cb.require_zero("first step, pc = 0", cur_step.state.pc.expr());
                cb.require_zero(
                    "first step, frame_index = 0",
                    cur_step.state.frame_index.expr(),
                );
                // cb.require_zero(
                //     "first step, module_index = 0",
                //     step_curr.cells.module_index.expr(),
                // );
                cb.require_zero(
                    "first step, function_index = 0",
                    cur_step.state.function_index.expr(),
                );
            });
            cb.gate(s_usable)
        });
        meta.create_gate("execution state constraints", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let s_step_last = vc.query_selector(s_step_last);
            let execution_state_selector_constraints = cur_step.state.conditions.configure();
            let first_step_check = {
                let begin_opcode_selector =
                    cur_step.execution_state_selector([Opcode::Call, Opcode::CallGeneric]);
                iter::once((
                    "First step should be Call/CallGeneric",
                    s_step_first * (1u64.expr() - begin_opcode_selector),
                ))
            };

            let last_step_check = {
                let end_opcode_selector = cur_step.execution_state_selector([Opcode::Nop]);
                iter::once((
                    "Last step should be Nop",
                    s_step_last * (1u64.expr() - end_opcode_selector),
                ))
            };

            execution_state_selector_constraints
                .into_iter()
                .map(move |(name, poly)| (name, s_usable.clone() * poly))
                .chain(first_step_check)
                .chain(last_step_check)
        });
        // meta.create_gate("q_step_last", |meta| {
        //     let q_usable = meta.query_fixed(q_usable, Rotation::cur());
        //     let q_step_last = meta.query_selector(q_step_last);
        //     let q_step = meta.query_advice(q_step, Rotation::cur());
        //     let mut cb = BaseConstraintBuilder::default();
        //     // q_step needs to be enabled on the last row
        //     cb.condition(q_usable, |cb| {
        //         cb.require_equal("q_step == 1", q_step.clone(), 1.expr());
        //     });
        //     cb.gate(q_step_last)
        // });
        meta.create_gate("clk", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(1u64.expr() - s_step_first, |cb| {
                cb.require_zero(
                    "clk(0) == clk(-1) | clk(0) == clk(-1)+2",
                    (cur_step.state.clk.expr() - prev_step.state.clk.expr())
                        * (cur_step.state.clk.expr() - prev_step.state.clk.expr() - 2u64.expr()),
                );
            });
            cb.gate(s_usable)
        });
        let first_row_selector =
            cur_step.state.clk.expr() - prev_step.state.clk.expr() - 1u64.expr();
        ExecChipConfig {
            s_usable,
            s_step_first,
            advices,
            step: cur_step,
        }
    }
}
