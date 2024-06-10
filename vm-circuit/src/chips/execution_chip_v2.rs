use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::{
    BaseConstraintBuilder, ConstrainBuilderCommon,
};
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::executions::base::BaseConstraintGadget;
use crate::chips::execution_chip_v2::executions::call::{CallStage1, CallStage2, CallStage3};
use crate::chips::execution_chip_v2::executions::pop::Pop;
use crate::chips::execution_chip_v2::executions::ret::Ret;
// use crate::chips::execution_chip_v2::executions::vec_push_back::{
//     VecPushBackStage1, VecPushBackStage2, VecPushBackStage3,
// };
// use crate::chips::execution_chip_v2::executions::vec_swap::{
//     VecSwapStage_1, VecSwapStage_2, VecSwapStage_3_Or_4, VecSwapStage_5_Or_6,
// };
// use crate::chips::execution_chip_v2::executions::{
//     VecPopBackStage1, VecPopBackStage2, VecPopBackStage3,
// };
use crate::chips::execution_chip_v2::executions::{BorrowLoc, BrBool, ExecutionState};
use crate::chips::execution_chip_v2::executions::{Ld, LdBool};
// use crate::chips::execution_chip_v2::executions::Pack;
use crate::chips::execution_chip_v2::executions::MoveOrCopyLoc;
use crate::chips::execution_chip_v2::lookup_table::{LookupTableConfigV2, Table};
use crate::chips::execution_chip_v2::step_v2::Step;
use crate::chips::execution_chip_v2::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use crate::chips::utilities::Expr;
use crate::table::LookupTable;
use crate::utils::cell_manager::CellType;
use crate::utils::cell_placement_strategy::CMFixedWidthStrategyDistribution;
use crate::utils::challenges::Challenges;
use crate::utils::rlc::rlc;
use gadgets::util::{and, not, or};
use halo2_proofs::plonk::{ConstraintSystem, Expression, Selector, VirtualCells};
use std::iter;
use types::Field;

pub(crate) mod call_stack;
pub(crate) mod executions;
pub(crate) mod lookup_table;
pub(crate) mod math_gadgets;
pub(crate) mod step_v2;
pub(crate) mod utils;
pub(crate) mod value;

#[derive(Clone)]
pub(crate) struct ExecChipConfig<F> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub advices: CMFixedWidthStrategyDistribution,
    pub br_true: Box<BrBool<F, true>>,
    pub br_false: Box<BrBool<F, false>>,
    pub ld_u8: Box<Ld<F, NUM_OF_BYTES_U8>>,
    pub ld_u16: Box<Ld<F, NUM_OF_BYTES_U16>>,
    pub ld_u32: Box<Ld<F, NUM_OF_BYTES_U32>>,
    pub ld_u64: Box<Ld<F, NUM_OF_BYTES_U64>>,
    pub ld_u128: Box<Ld<F, NUM_OF_BYTES_U128>>,
    pub ld_u256: Box<Ld<F, NUM_OF_BYTES_U256>>,
    pub ld_true: Box<LdBool<F, true>>,
    pub ld_false: Box<LdBool<F, false>>,
    // pub pack: Box<Pack<F>>,
    pub imm_borrow_loc: Box<BorrowLoc<false, F>>,
    // pub vec_swap_stage_1: Box<VecSwapStage_1<F>>,
    // pub vec_swap_stage_2: Box<VecSwapStage_2<F>>,
    // pub vec_swap_stage_3: Box<VecSwapStage_3_Or_4<F, true>>,
    // pub vec_swap_stage_4: Box<VecSwapStage_3_Or_4<F, false>>,
    // pub vec_swap_stage_5: Box<VecSwapStage_5_Or_6<F, true>>,
    // pub vec_swap_stage_6: Box<VecSwapStage_5_Or_6<F, false>>,
    // pub vec_pop_back_stage1: Box<VecPopBackStage1<F>>,
    // pub vec_pop_back_stage2: Box<VecPopBackStage2<F>>,
    // pub vec_pop_back_stage3: Box<VecPopBackStage3<F>>,
    // pub vec_push_back_stage1: Box<VecPushBackStage1<F>>,
    // pub vec_push_back_stage2: Box<VecPushBackStage2<F>>,
    // pub vec_push_back_stage3: Box<VecPushBackStage3<F>>,
    pub pop: Box<Pop<F>>,
    pub move_loc: Box<MoveOrCopyLoc<F, true>>,
    pub copy_loc: Box<MoveOrCopyLoc<F, false>>,
    pub call_stage_1: Box<CallStage1<F>>,
    pub call_stage_2: Box<CallStage2<F>>,
    pub call_stage_3: Box<CallStage3<F>>,
    pub ret: Box<Ret<F>>,
    pub step: Step<F>,
}

impl<F: Field> ExecChipConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenges: Challenges<Expression<F>>,
        lookup_table_configs: LookupTableConfigV2<F>,
    ) -> Self {
        let s_usable = meta.complex_selector();
        let s_step_first = meta.complex_selector();
        let s_step_last = meta.complex_selector();
        let advices: CMFixedWidthStrategyDistribution = cm_distribute_advice(meta);
        let step_curr = Step::new(meta, advices.clone(), 0, &challenges);
        let step_next = Step::new(meta, advices.clone(), 1, &challenges);
        let _step_prev = Step::new(meta, advices.clone(), -1, &challenges);
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
            let execution_state_selector_constraints = step_curr.state.execution_state.configure();
            let first_step_check = {
                let begin_opcode_selector =
                    step_curr.execution_state_selector([ExecutionState::Start]);
                iter::once((
                    "First step should be Call/CallGeneric",
                    s_step_first * (1u64.expr() - begin_opcode_selector),
                ))
            };

            let last_step_check = {
                let end_opcode_selector = step_curr.execution_state_selector([ExecutionState::Nop]);
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
            let s_step_last = vc.query_selector(s_step_last);
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(1u64.expr() - s_step_last.clone(), |cb| {
                // FIXME: for now,we increase clk by one for each bytecode
                // we need to figure out how to constraint vec_swap.
                cb.require_boolean(
                    "clk(1) - clk(0)  == 0 | 1",
                    step_next.state.clk.expr() - step_curr.state.clk.expr(),
                );
            });
            cb.gate(s_usable)
        });

        // base configuration for every opcode gadgets
        let step_curr = {
            let mut cb = ConstraintBuilderV2::new(meta, &challenges, step_curr, None);
            BaseConstraintGadget::configure(&mut cb);
            // we need to reuse the step_curr when configuring opcode gadgets.
            let step_curr = cb.curr.clone();
            Self::configure_opcode_gadget_impl(
                s_usable,
                s_step_first,
                s_step_last,
                "base constraints",
                cb,
            );
            step_curr
        };
        macro_rules! configure_opcode_gadget {
            () => {
                Box::new(Self::configure_opcode_gadget(
                    meta,
                    &challenges,
                    advices.clone(),
                    s_usable,
                    s_step_first,
                    s_step_last,
                    &step_curr,
                ))
            };
        }

        let config = ExecChipConfig {
            s_usable,
            s_step_first,
            br_true: configure_opcode_gadget!(),
            br_false: configure_opcode_gadget!(),
            ld_u8: configure_opcode_gadget!(),
            ld_u16: configure_opcode_gadget!(),
            ld_u32: configure_opcode_gadget!(),
            ld_u64: configure_opcode_gadget!(),
            ld_u128: configure_opcode_gadget!(),
            ld_u256: configure_opcode_gadget!(),
            ld_true: configure_opcode_gadget!(),
            ld_false: configure_opcode_gadget!(),
            imm_borrow_loc: configure_opcode_gadget!(),
            // pack: configure_opcode_gadget!(),
            // vec_swap_stage_1: configure_opcode_gadget!(),
            // vec_swap_stage_2: configure_opcode_gadget!(),
            // vec_swap_stage_3: configure_opcode_gadget!(),
            // vec_swap_stage_4: configure_opcode_gadget!(),
            // vec_swap_stage_5: configure_opcode_gadget!(),
            // vec_swap_stage_6: configure_opcode_gadget!(),
            // vec_pop_back_stage1: configure_opcode_gadget!(),
            // vec_pop_back_stage2: configure_opcode_gadget!(),
            // vec_pop_back_stage3: configure_opcode_gadget!(),
            // vec_push_back_stage1: configure_opcode_gadget!(),
            // vec_push_back_stage2: configure_opcode_gadget!(),
            // vec_push_back_stage3: configure_opcode_gadget!(),
            pop: configure_opcode_gadget!(),
            move_loc: configure_opcode_gadget!(),
            copy_loc: configure_opcode_gadget!(),
            call_stage_1: configure_opcode_gadget!(),
            call_stage_2: configure_opcode_gadget!(),
            call_stage_3: configure_opcode_gadget!(),
            ret: configure_opcode_gadget!(),
            advices: advices.clone(),
            step: step_curr,
        };
        Self::configure_lookup(
            meta,
            &challenges,
            &lookup_table_configs,
            &config.step,
            s_usable,
        );
        Self::configure_shuffle(meta, &config, s_usable);

        config
    }

    fn configure_opcode_gadget<G: InstructionGadgetV2<F>>(
        meta: &mut ConstraintSystem<F>,
        challenges: &Challenges<Expression<F>>,
        //lookups: &mut Vec<(&'static str, ConditionalLookup<F>)>,
        _advices: CMFixedWidthStrategyDistribution,
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        //s_step: Column<Advice>,
        step_curr: &Step<F>,
    ) -> G {
        // Now actually configure the gadget with the correct minimal height
        let mut cb = ConstraintBuilderV2::new(
            meta,
            challenges,
            step_curr.clone(),
            Some(G::EXECUTION_STATE),
        );
        let gadget = G::configure(&mut cb);
        Self::configure_opcode_gadget_impl(s_usable, s_step_first, s_step_last, G::NAME, cb);
        gadget
    }

    fn configure_opcode_gadget_impl(
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        name: &'static str,
        mut cb: ConstraintBuilderV2<F>,
    ) {
        let step_prev = cb.step_state_at_offset(-1);
        let step_next = cb.step_state_at_offset(1);
        let (step_curr, constraints, _store_expressions, meta) = cb.build();
        // Enforce the logic for this opcode
        let first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first);
            or::expr([
                row0,
                step_curr.state.clk.expr() - step_prev.clk.expr(), /* = 1 */
            ])
        };

        let last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last);
            or::expr([
                row_n,
                step_next.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
            ])
        };
        let not_first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first);
            and::expr([
                not::expr(row0),
                not::expr(
                    step_curr.state.clk.expr() - step_prev.clk.expr(), /* = 1 */
                ),
            ])
        };
        let not_last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last);
            and::expr([
                not::expr(row_n),
                not::expr(
                    step_next.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
                ),
            ])
        };

        for (selector, constraints) in [
            (first_row, constraints.first_row),
            (last_row, constraints.last_row),
            (not_first_row, constraints.not_first_row),
            (not_last_row, constraints.not_last_row),
            (&|_| 1.expr(), constraints.any_row),
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

    #[allow(clippy::too_many_arguments)]
    fn configure_lookup(
        meta: &mut ConstraintSystem<F>,
        challenges: &Challenges<Expression<F>>,
        lookup_table_config: &LookupTableConfigV2<F>,
        step_curr: &Step<F>,
        s_usable: Selector,
    ) {
        meta.lookup_any("bytecode_lookup", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let table_expressions = lookup_table_config.bytecode_table.table_exprs(meta);
            [
                step_curr.state.module_index.expr(),
                step_curr.state.function_index.expr(),
                step_curr.state.pc.expr(),
                step_curr.state.opcode.expr(),
                step_curr.state.aux0.expr(),
                step_curr.state.aux1.expr(),
            ]
            .into_iter()
            .map(|e| s_usable.clone() * e)
            .zip(table_expressions)
            .collect()
        });
        for column in step_curr.cell_manager.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                let name = format!("{:?}", table);
                let column_expr = column.expr(meta);
                meta.lookup_any(name.as_str(), |meta| {
                    let s_usable = meta.query_selector(s_usable);
                    let table_expressions = match table {
                        Table::U8 => lookup_table_config.u8_table.table_exprs(meta),
                        Table::U16 => lookup_table_config.u16_table.table_exprs(meta),
                        Table::Function => lookup_table_config.function_table.table_exprs(meta),
                        _ => unimplemented!(),
                    };
                    vec![(
                        s_usable * column_expr,
                        rlc::expr(&table_expressions, challenges.lookup_input()),
                    )]
                });
            }
        }
    }

    fn configure_shuffle(
        meta: &mut ConstraintSystem<F>,
        config: &ExecChipConfig<F>,
        s_usable: Selector,
    ) {
        let step_curr = &config.step;
        meta.shuffle("stack consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let pop_set = [
                step_curr.state.stack_pop_index.expr(),
                step_curr.state.stack_pop_sub_index.expr(),
                step_curr.state.stack_pop_value_header.expr(),
                step_curr.state.stack_pop_version.expr(),
            ]
            .into_iter()
            .chain(step_curr.state.stack_pop_value.exprs().into_iter())
            .map(|e| s_usable.clone() * e);
            let push_set = [
                step_curr.state.stack_push_index.expr(),
                step_curr.state.stack_push_sub_index.expr(),
                step_curr.state.stack_push_value_header.expr(),
                step_curr.state.stack_push_version.expr(),
            ]
            .into_iter()
            .chain(step_curr.state.stack_push_value.exprs().into_iter())
            .map(|e| s_usable.clone() * e);
            pop_set.zip(push_set).collect()
        });
        meta.shuffle("local consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let read_set = [
                step_curr.state.local_frame_index.expr(),
                step_curr.state.local_index.expr(),
                step_curr.state.local_sub_index.expr(),
                step_curr.state.local_read_value_header.expr(),
                step_curr.state.local_read_value_invalid.expr(),
                step_curr.state.local_read_version.expr(),
            ]
            .into_iter()
            .chain(step_curr.state.local_read_value.exprs().into_iter())
            .map(|e| s_usable.clone() * e);
            let write_set = [
                step_curr.state.local_frame_index.expr(),
                step_curr.state.local_index.expr(),
                step_curr.state.local_sub_index.expr(),
                step_curr.state.local_write_value_header.expr(),
                step_curr.state.local_write_value_invalid.expr(),
                step_curr.state.local_write_version.expr(),
            ]
            .into_iter()
            .chain(step_curr.state.local_write_value.exprs().into_iter())
            .map(|e| s_usable.clone() * e);
            read_set.zip(write_set).collect()
        });

        meta.shuffle("callstack consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let s_callstack_push = step_curr
                .execution_state_selector([ExecutionState::CallStage1, ExecutionState::CallStage3]);
            let input_exprs = config
                .call_stage_1 // either call_stage_1 or call_stage_3 is ok
                .call_context
                .exprs()
                .into_iter()
                .map(|e| s_usable.clone() * s_callstack_push.clone() * e);
            let s_callstack_pop = step_curr.execution_state_selector([ExecutionState::Ret]);
            let shuffled_exprs = config
                .ret
                .call_context
                .exprs()
                .into_iter()
                .map(|e| s_usable.clone() * s_callstack_pop.clone() * e);
            input_exprs.into_iter().zip(shuffled_exprs).collect()
        });
    }
}

pub(crate) trait InstructionGadgetV2<F: Field> {
    const NAME: &'static str;

    const OPCODE: Opcode;
    const EXECUTION_STATE: ExecutionState;

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

/// FIXME: setup columns
#[allow(clippy::mut_range_bound)]
pub(crate) fn cm_distribute_advice<F: Field>(
    _meta: &mut ConstraintSystem<F>,
    // advices: &[Column<Advice>],
) -> CMFixedWidthStrategyDistribution {
    // let mut column_idx = 0;
    // // Mark columns used for lookups in Phase3
    // for &(table, count) in LOOKUP_CONFIG {
    //     for _ in 0usize..count {
    //         dist.add(CellType::Lookup(table), advices[column_idx]);
    //         column_idx += 1;
    //     }
    // }
    //
    // // Mark columns used for Phase2 constraints
    // for _ in 0..N_PHASE2_COLUMNS {
    //     dist.add(CellType::StoragePhase2, advices[column_idx]);
    //     column_idx += 1;
    // }
    //
    // // Mark columns used for copy constraints
    // for _ in 0..N_COPY_COLUMNS {
    //     meta.enable_equality(advices[column_idx]);
    //     dist.add(CellType::StoragePermutation, advices[column_idx]);
    //     column_idx += 1;
    // }
    //
    // // Mark columns used for byte lookup
    // #[allow(clippy::reversed_empty_ranges)]
    // for _ in 0..N_U8_LOOKUPS {
    //     dist.add(CellType::Lookup(Table::U8), advices[column_idx]);
    //     assert_eq!(advices[column_idx].column_type().phase(), 0);
    //     column_idx += 1;
    // }
    //
    // // Mark columns used for byte lookup
    // #[allow(clippy::reversed_empty_ranges)]
    // for _ in 0..N_U16_LOOKUPS {
    //     dist.add(CellType::Lookup(Table::U16), advices[column_idx]);
    //     assert_eq!(advices[column_idx].column_type().phase(), 0);
    //     column_idx += 1;
    // }
    //
    // // Mark columns used for for Phase1 constraints
    // for _ in column_idx..advices.len() {
    //     dist.add(CellType::StoragePhase1, advices[column_idx]);
    //     column_idx += 1;
    // }

    CMFixedWidthStrategyDistribution::default()
}
