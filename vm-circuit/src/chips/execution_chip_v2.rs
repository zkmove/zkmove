use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::STEP_CHIP_WIDTH;
use crate::chips::execution_chip::step_v2::Step;
use crate::chips::execution_chip::utils::base_constraint_builder::{
    BaseConstraintBuilder, ConstrainBuilderCommon,
};

use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::utilities::Expr;
use gadgets::util::{and, not, or};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Expression, FirstPhase, Selector, VirtualCells,
};

use crate::chips::execution_chip_v2::executions::BrBool;
use std::iter;
use types::Field;

mod executions;

#[derive(Clone)]
pub struct ExecChipConfig<F> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub advices: [Column<Advice>; STEP_CHIP_WIDTH],
    pub br_true: Box<BrBool<F, true>>,
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
        let step_curr = Step::new(meta, advices, 0);
        let step_prev = Step::new(meta, advices, -1);
        let step_next = Step::new(meta, advices, 1);
        meta.create_gate("s_step_first", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(s_step_first.clone(), |cb| {
                cb.require_zero("first step, clk = 0", step_curr.state.clk.expr());
                cb.require_zero("first step, pc = 0", step_curr.state.pc.expr());
                cb.require_zero(
                    "first step, frame_index = 0",
                    step_curr.state.frame_index.expr(),
                );
                // cb.require_zero(
                //     "first step, module_index = 0",
                //     step_curr.cells.module_index.expr(),
                // );
                cb.require_zero(
                    "first step, function_index = 0",
                    step_curr.state.function_index.expr(),
                );
            });
            cb.gate(s_usable)
        });
        meta.create_gate("execution state constraints", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let s_step_last = vc.query_selector(s_step_last);
            let execution_state_selector_constraints = step_curr.state.conditions.configure();
            let first_step_check = {
                let begin_opcode_selector =
                    step_curr.execution_state_selector([Opcode::Call, Opcode::CallGeneric]);
                iter::once((
                    "First step should be Call/CallGeneric",
                    s_step_first * (1u64.expr() - begin_opcode_selector),
                ))
            };

            let last_step_check = {
                let end_opcode_selector = step_curr.execution_state_selector([Opcode::Nop]);
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
            cb.condition(1u64.expr() - s_step_first.clone(), |cb| {
                // FIXME: for now,we increase clk by one for each bytecode
                // we need to figure out how to constraint vec_swap.
                cb.require_boolean(
                    "clk(0) - clk(-1)  == 0 | 1",
                    step_curr.state.clk.expr() - step_prev.state.clk.expr(),
                );
            });
            cb.gate(s_usable)
        });

        // common constraint for every opcode
        // meta.create_gate("first_row_of_bytecode", |meta| {});
        meta.create_gate("last_row_of_bytecode", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let row_n = meta.query_selector(s_step_last);
            let last_row_selector = or::expr([
                row_n,
                step_next.state.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
            ]);
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(last_row_selector, |cb| {
                cb.require_equal(
                    "step_counter(0)==1",
                    step_curr.state.step_counter.expr(),
                    1u64.expr(),
                );
            });
            cb.gate(s_usable)
        });

        meta.create_gate("not_last_row_of_bytecode", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let row_n = meta.query_selector(s_step_last);
            let not_last_row_selector = and::expr([
                not::expr(row_n),
                not::expr(
                    step_next.state.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
                ),
            ]);
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(not_last_row_selector, |cb| {
                cb.require_equal(
                    "frame_index(1)==frame_index(0)",
                    step_next.state.frame_index.expr(),
                    step_curr.state.frame_index.expr(),
                );
                cb.require_equal(
                    "module_index(1)==module_index(0)",
                    step_next.state.module_index.expr(),
                    step_curr.state.module_index.expr(),
                );
                cb.require_equal(
                    "function_index(1)==function_index(0)",
                    step_next.state.function_index.expr(),
                    step_curr.state.function_index.expr(),
                );
                cb.require_equal(
                    "opcode(1)==opcode(0)",
                    step_next.state.opcode.expr(),
                    step_curr.state.opcode.expr(),
                );
                cb.require_equal(
                    "pc(1)==pc(0)",
                    step_next.state.pc.expr(),
                    step_curr.state.pc.expr(),
                );
                // TODO: check on aux0 and aux1
            });
            cb.gate(s_usable)
        });

        macro_rules! configure_opcode_gadget {
            () => {
                Box::new(Self::configure_opcode_gadget(
                    meta,
                    advices,
                    s_usable,
                    s_step_first,
                    s_step_last,
                    &step_curr,
                ))
            };
        }

        ExecChipConfig {
            s_usable,
            s_step_first,
            advices,
            br_true: configure_opcode_gadget!(),
            step: step_curr,
        }
    }

    fn configure_opcode_gadget<G: InstructionGadgetV2<F>>(
        meta: &mut ConstraintSystem<F>,
        //lookups: &mut Vec<(&'static str, ConditionalLookup<F>)>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        //s_step: Column<Advice>,
        step_curr: &Step<F>,
    ) -> G {
        // Now actually configure the gadget with the correct minimal height
        let step_next = Step::new(meta, advices, 1);
        let step_prev = Step::new(meta, advices, -1);
        let mut cb =
            ConstraintBuilderV2::new(meta, step_curr.clone(), step_next.clone(), G::OPCODE);
        let gadget = G::configure(&mut cb);
        Self::configure_opcode_gadget_impl(
            advices,
            s_usable,
            s_step_first,
            s_step_last,
            &step_curr,
            &step_prev,
            &step_next,
            G::NAME,
            G::OPCODE,
            cb,
        );

        gadget
    }

    fn configure_opcode_gadget_impl(
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        step_curr: &Step<F>,
        step_prev: &Step<F>,
        step_next: &Step<F>,
        name: &'static str,
        opcode: Opcode,
        mut cb: ConstraintBuilderV2<F>,
    ) {
        let (constraints, _lookups, meta) = cb.build();
        // Enforce the logic for this opcode
        let first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first.clone());
            or::expr([
                row0,
                step_curr.state.clk.expr() - step_prev.state.clk.expr(), /* = 1 */
            ])
        };

        let last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last.clone());
            or::expr([
                row_n,
                step_next.state.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
            ])
        };
        let not_first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first.clone());
            and::expr([
                not::expr(row0),
                not::expr(
                    step_curr.state.clk.expr() - step_prev.state.clk.expr(), /* = 1 */
                ),
            ])
        };
        let not_last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last.clone());
            and::expr([
                not::expr(row_n),
                not::expr(
                    step_next.state.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
                ),
            ])
        };

        for (selector, constraints) in [
            (first_row, constraints.first_row),
            (last_row, constraints.last_row),
            (not_first_row, constraints.not_first_row),
            (not_last_row, constraints.not_last_row),
        ] {
            if !constraints.is_empty() {
                meta.create_gate(name, |meta| {
                    let q_usable = meta.query_selector(s_usable);
                    let selector = selector(meta);
                    constraints.into_iter().map(move |(name, constraint)| {
                        (name, q_usable.clone() * selector.clone() * constraint)
                    })
                });
            }
        }
    }
}

pub(crate) trait InstructionGadgetV2<F: Field> {
    const NAME: &'static str;

    const OPCODE: Opcode;

    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self;

    // fn assign(
    //     &self,
    //     region: &mut Region<'_, F>,
    //     offset: usize,
    //     step: &ExecutionStep,
    //     rw_operations: &RWOperations,
    //     cells: &StepChipCells<F>,
    // ) -> Result<(), Error>;

    // fn construct(cb: &mut ConstraintBuilder<F>) -> Self;
}
