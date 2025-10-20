use crate::execution_circuit::executions::abort::Abort;
use crate::execution_circuit::executions::branch::Branch;
use crate::execution_circuit::executions::error::ErrorState;
use crate::execution_circuit::executions::nop::Nop;
use crate::execution_circuit::executions::start::{ProcessArg, Start};
use crate::execution_circuit::executions::stop::Stop;
use crate::execution_circuit::executions::teardown::Teardown;
use crate::execution_circuit::executions::BaseConstraintGadget;
use crate::execution_circuit::executions::{
    AddSub, AndOr, BitwiseStage1, BitwiseStage2, BorrowField, BorrowLoc, BrBool, CallStage1,
    CallStage2, CallStage3, Cast, Equality, LdBool, LdConst, LdSimple, Le, Lt, MoveOrCopyLoc,
    MulDivModStage1, MulDivModStage2, NativePoseidonHash, Not, Pack, Pop, ReadRef, Ret,
    ShiftStage1, ShiftStage2, StoreLocStage1, StoreLocStage2, UnpackStage1, UnpackStage2,
    VecBorrow, VecLen, VecPopBackStage1, VecPopBackStage2, VecPushBackStage1, VecPushBackStage2,
    VecSwapStage_1, VecSwapStage_2_Or_3, VecSwapStage_4_Or_5, WriteRefStage1, WriteRefStage2,
    WriteRefStage3,
};
use crate::execution_circuit::lookup_table::LookupTableConfigV2;
use crate::execution_circuit::step::{Step, StepState};
use crate::public_inputs::InstanceTable;
use crate::table::LookupTable;
use crate::utils::base_constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{CellManagerColumns, CellType};
use crate::utils::challenges::Challenges;
use crate::utils::constraint_builder_v2::{
    ConstraintBuilderV2, ConstraintLocation, Constraints, Lookups, StoredExpressions,
};
use crate::utils::rlc;
use gadgets::util;
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{
    ConstraintSystem, ErrorFront as Error, Expression, FirstPhase, SecondPhase, Selector,
    VirtualCells,
};
use move_binary_format::file_format_common::Opcodes;
use poseidon_base::Hashable;
use std::collections::BTreeMap;
use std::iter;
use types::Field;
use witnesses::static_info::StaticInfo;
use witnesses::step_state::StageState;

pub(crate) mod abort;
pub(crate) mod add_sub;
pub(crate) mod and_or;
pub(crate) mod base;
pub(crate) mod bitwise;
pub(crate) mod borrow_field;
pub(crate) mod borrow_loc;
pub(crate) mod br_bool;
pub(crate) mod branch;
pub(crate) mod call;
pub(crate) mod cast;
pub(crate) mod equality;
pub(crate) mod error;
pub(crate) mod ld;
pub(crate) mod ld_bool;
pub(crate) mod ld_const;
pub(crate) mod le_gt;
pub(crate) mod lt_ge;
pub(crate) mod move_or_copy_loc;
pub(crate) mod mul_div_mod;
pub(crate) mod nop;
pub(crate) mod not;
pub(crate) mod pack;
pub(crate) mod pop;
pub(crate) mod read_ref;
pub(crate) mod ret;
pub(crate) mod shl_shr;
pub(crate) mod start;
pub(crate) mod stop;
pub(crate) mod store_loc;
pub(crate) mod teardown;
pub(crate) mod unpack;
pub(crate) mod vec_borrow;
pub(crate) mod vec_len;
pub(crate) mod vec_pop_back;
pub(crate) mod vec_push_back;
pub(crate) mod vec_swap;
pub(crate) mod write_ref;

pub(crate) mod native_poseidon_hash;

pub(crate) use add_sub::*;
pub(crate) use and_or::*;
pub(crate) use base::*;
pub(crate) use bitwise::*;
pub(crate) use borrow_field::*;
pub(crate) use borrow_loc::*;
pub(crate) use br_bool::*;
pub(crate) use call::*;
pub(crate) use cast::*;
pub(crate) use equality::*;
pub(crate) use ld::*;
pub(crate) use ld_bool::*;
pub(crate) use ld_const::*;
pub(crate) use le_gt::*;
pub(crate) use lt_ge::*;
pub(crate) use move_or_copy_loc::*;
pub(crate) use mul_div_mod::*;
pub(crate) use native_poseidon_hash::*;
pub(crate) use not::*;
pub(crate) use pack::*;
pub(crate) use pop::*;
pub(crate) use read_ref::*;
pub(crate) use ret::*;
pub(crate) use shl_shr::*;
pub(crate) use store_loc::*;
pub(crate) use unpack::*;
pub(crate) use vec_borrow::*;
pub(crate) use vec_len::*;
pub(crate) use vec_pop_back::*;
pub(crate) use vec_push_back::*;
pub(crate) use vec_swap::*;
pub(crate) use write_ref::*;

pub(crate) use crate::execution_circuit::sub_index::*;
pub(crate) use witnesses::step_state::ExecutionState;

#[derive(Clone)]
pub(crate) struct ExecutionConfig<F> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub s_step_last: Selector,
    pub columns: CellManagerColumns,
    pub base_constraint: Box<BaseConstraintGadget<F>>,
    pub start: Option<Box<Start<F>>>,
    pub process_arg: Option<Box<ProcessArg<F>>>,
    pub abort: Option<Box<Abort<F>>>,
    pub error: Option<Box<ErrorState<F>>>,
    pub add_sub: Option<Box<AddSub<F>>>,
    pub and_or: Option<Box<AndOr<F>>>,
    pub bitwise_stage1: Option<Box<BitwiseStage1<F, 8, 8>>>,
    pub bitwise_stage2: Option<Box<BitwiseStage2<F, 8, 8>>>,
    pub borrow_field: Option<Box<BorrowField<F>>>,
    pub borrow_loc: Option<Box<BorrowLoc<F>>>,
    pub br_true: Option<Box<BrBool<F, true>>>,
    pub br_false: Option<Box<BrBool<F, false>>>,
    pub branch: Option<Box<Branch<F>>>,
    pub call_stage_1: Option<Box<CallStage1<F>>>,
    pub call_stage_2: Option<Box<CallStage2<F>>>,
    pub call_stage_3: Option<Box<CallStage3<F>>>,
    pub cast: Option<Box<Cast<F>>>,
    pub copy_loc: Option<Box<MoveOrCopyLoc<F, false>>>,
    pub eq_stage_1: Option<Box<Equality<F, true, true>>>,
    pub eq_stage_2: Option<Box<Equality<F, false, true>>>,
    pub ge: Option<Box<Lt<F, false>>>,
    pub gt: Option<Box<Le<F, false>>>,
    pub ld_simple: Option<Box<LdSimple<F>>>,
    pub ld_true: Option<Box<LdBool<F, true>>>,
    pub ld_false: Option<Box<LdBool<F, false>>>,
    pub ld_const: Option<Box<LdConst<F>>>,
    pub le: Option<Box<Le<F, true>>>,
    pub lt: Option<Box<Lt<F, true>>>,
    pub move_loc: Option<Box<MoveOrCopyLoc<F, true>>>,
    pub mul_div_mod_stage1: Option<Box<MulDivModStage1<F>>>,
    pub mul_div_mod_stage2: Option<Box<MulDivModStage2<F>>>,
    pub native_poseidon_hash: Option<Box<NativePoseidonHash<F>>>,
    pub neq_stage_1: Option<Box<Equality<F, true, false>>>,
    pub neq_stage_2: Option<Box<Equality<F, false, false>>>,
    pub not: Option<Box<Not<F>>>,
    pub pack: Option<Box<Pack<F, false>>>,
    pub pop: Option<Box<Pop<F>>>,
    pub read_ref: Option<Box<ReadRef<F>>>,
    pub ret: Option<Box<Ret<F>>>,
    pub shift_stage1: Option<Box<ShiftStage1<F>>>,
    pub shift_stage2: Option<Box<ShiftStage2<F>>>,
    pub store_loc_stage1: Option<Box<StoreLocStage1<F>>>,
    pub store_loc_stage2: Option<Box<StoreLocStage2<F>>>,
    pub unpack_stage_1: Option<Box<UnpackStage1<F, false>>>,
    pub unpack_stage_2: Option<Box<UnpackStage2<F, false>>>,
    pub vec_borrow: Option<Box<VecBorrow<F>>>,
    pub vec_len: Option<Box<VecLen<F>>>,
    pub vec_pack: Option<Box<Pack<F, true>>>,
    pub vec_pop_back_stage1: Option<Box<VecPopBackStage1<F>>>,
    pub vec_pop_back_stage2: Option<Box<VecPopBackStage2<F>>>,
    pub vec_push_back_stage1: Option<Box<VecPushBackStage1<F>>>,
    pub vec_push_back_stage2: Option<Box<VecPushBackStage2<F>>>,
    pub vec_swap_stage_1: Option<Box<VecSwapStage_1<F>>>,
    pub vec_swap_stage_2: Option<Box<VecSwapStage_2_Or_3<F, true>>>,
    pub vec_swap_stage_3: Option<Box<VecSwapStage_2_Or_3<F, false>>>,
    pub vec_swap_stage_4: Option<Box<VecSwapStage_4_Or_5<F, true>>>,
    pub vec_swap_stage_5: Option<Box<VecSwapStage_4_Or_5<F, false>>>,
    pub vec_unpack_stage_1: Option<Box<UnpackStage1<F, true>>>,
    pub vec_unpack_stage_2: Option<Box<UnpackStage2<F, true>>>,
    pub write_ref_stage1: Option<Box<WriteRefStage1<F>>>,
    pub write_ref_stage2: Option<Box<WriteRefStage2<F>>>,
    pub write_ref_stage3: Option<Box<WriteRefStage3<F>>>,
    pub nop: Option<Box<Nop<F>>>,
    pub teardown: Option<Box<Teardown<F>>>,
    pub stop: Option<Box<Stop<F>>>,
    pub step: Step<F>,
    pub challenges: Challenges,
    pub stored_expressions_map: BTreeMap<Option<ExecutionState>, StoredExpressions<F>>,
    pub dynamic_cell_stat_map: BTreeMap<ExecutionState, BTreeMap<CellType, usize>>,
    pub instances: InstanceTable,
}

impl<F: Field + Hashable> ExecutionConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lookup_table_configs: &LookupTableConfigV2<F>,
        used_opcodes: &[Opcodes],
    ) -> Self {
        let s_usable = meta.complex_selector();
        let s_step_first = meta.complex_selector();
        let s_step_last = meta.complex_selector();

        let mut cell_columns = CellManagerColumns::default();
        // these're needed to make Challenges construction work.
        cell_columns.add_column(CellType::StoragePhase0, meta.advice_column_in(FirstPhase));
        cell_columns.add_column(CellType::StoragePhase1, meta.advice_column_in(SecondPhase));

        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        let step_curr = Step::new(meta, &mut cell_columns, 0, &challenge_exprs);
        let step_next = Step::new(meta, &mut cell_columns, 1, &challenge_exprs);
        meta.create_gate("s_step_first", |vc| {
            let s_usable = vc.query_selector(s_usable);
            let s_step_first = vc.query_selector(s_step_first);
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(s_step_first.clone(), |cb| {
                // 0 is special and represents empty operations, so clk starts at 1
                cb.require_equal(
                    "first step, clk = 1",
                    step_curr.state.clk.expr(),
                    1u64.expr(),
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
                    "First step should be Start",
                    s_step_first * (1u64.expr() - begin_opcode_selector),
                ))
            };

            let last_step_check = {
                let end_opcode_selector =
                    step_curr.execution_state_selector([ExecutionState::Stop]);
                iter::once((
                    "Last step should be Stop",
                    s_usable.clone() * s_step_last * (1u64.expr() - end_opcode_selector),
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
                cb.require_boolean(
                    "clk(1) - clk(0)  == 0 | 1",
                    step_next.state.clk.expr() - step_curr.state.clk.expr(),
                );
            });
            cb.gate(s_usable)
        });

        let mut constraints_map = BTreeMap::new();
        let mut lookup_map = BTreeMap::new();
        let mut stored_expressions_map = BTreeMap::new();
        let mut additional_cell_stat_map = BTreeMap::new();

        // base configuration for every opcode gadgets
        let (step_curr, base_constraint) = {
            let mut cb = ConstraintBuilderV2::new(
                meta,
                &mut cell_columns,
                &challenge_exprs,
                step_curr,
                None,
            );
            let base_constraint = BaseConstraintGadget::configure(&mut cb);

            // we need to reuse the step_curr when configuring opcode gadgets.
            let (step_curr, constraints, lookups, stored_expressions, _, _) = cb.build();

            constraints_map.insert(None, constraints);
            lookup_map.insert(None, lookups);
            stored_expressions_map.insert(None, stored_expressions);

            (step_curr, base_constraint)
        };
        let mut used_execution_states = ExecutionState::mandatory_states();
        used_execution_states.extend(ExecutionState::from_opcodes(used_opcodes));
        // temp solution to using `NativePoseidonHash` in the gadget
        used_execution_states.push(ExecutionState::NativePoseidonHash);
        macro_rules! build_opcode_gadget {
            () => {
                Self::build_opcode_gadget(
                    meta,
                    &mut cell_columns,
                    &challenge_exprs,
                    &step_curr,
                    &mut constraints_map,
                    &mut stored_expressions_map,
                    &mut lookup_map,
                    &mut additional_cell_stat_map,
                    &used_execution_states,
                )
            };
        }

        let instances = InstanceTable::construct(meta);

        let mut config = ExecutionConfig {
            s_usable,
            s_step_first,
            s_step_last,
            base_constraint: Box::new(base_constraint),
            start: build_opcode_gadget!(),
            process_arg: build_opcode_gadget!(),
            abort: build_opcode_gadget!(),
            error: build_opcode_gadget!(),
            add_sub: build_opcode_gadget!(),
            and_or: build_opcode_gadget!(),
            bitwise_stage1: build_opcode_gadget!(),
            bitwise_stage2: build_opcode_gadget!(),
            borrow_field: build_opcode_gadget!(),
            borrow_loc: build_opcode_gadget!(),
            br_true: build_opcode_gadget!(),
            br_false: build_opcode_gadget!(),
            branch: build_opcode_gadget!(),
            call_stage_1: build_opcode_gadget!(),
            call_stage_2: build_opcode_gadget!(),
            call_stage_3: build_opcode_gadget!(),
            cast: build_opcode_gadget!(),
            copy_loc: build_opcode_gadget!(),
            eq_stage_1: build_opcode_gadget!(),
            eq_stage_2: build_opcode_gadget!(),
            ge: build_opcode_gadget!(),
            gt: build_opcode_gadget!(),
            ld_simple: build_opcode_gadget!(),
            ld_true: build_opcode_gadget!(),
            ld_false: build_opcode_gadget!(),
            ld_const: build_opcode_gadget!(),
            le: build_opcode_gadget!(),
            lt: build_opcode_gadget!(),
            move_loc: build_opcode_gadget!(),
            mul_div_mod_stage1: build_opcode_gadget!(),
            mul_div_mod_stage2: build_opcode_gadget!(),
            native_poseidon_hash: build_opcode_gadget!(),
            neq_stage_1: build_opcode_gadget!(),
            neq_stage_2: build_opcode_gadget!(),
            not: build_opcode_gadget!(),
            pack: build_opcode_gadget!(),
            pop: build_opcode_gadget!(),
            read_ref: build_opcode_gadget!(),
            ret: build_opcode_gadget!(),
            store_loc_stage1: build_opcode_gadget!(),
            store_loc_stage2: build_opcode_gadget!(),
            shift_stage1: build_opcode_gadget!(),
            shift_stage2: build_opcode_gadget!(),
            teardown: build_opcode_gadget!(),
            unpack_stage_1: build_opcode_gadget!(),
            unpack_stage_2: build_opcode_gadget!(),
            vec_borrow: build_opcode_gadget!(),
            vec_len: build_opcode_gadget!(),
            vec_pack: build_opcode_gadget!(),
            vec_pop_back_stage1: build_opcode_gadget!(),
            vec_pop_back_stage2: build_opcode_gadget!(),
            vec_push_back_stage1: build_opcode_gadget!(),
            vec_push_back_stage2: build_opcode_gadget!(),
            vec_swap_stage_1: build_opcode_gadget!(),
            vec_swap_stage_2: build_opcode_gadget!(),
            vec_swap_stage_3: build_opcode_gadget!(),
            vec_swap_stage_4: build_opcode_gadget!(),
            vec_swap_stage_5: build_opcode_gadget!(),
            vec_unpack_stage_1: build_opcode_gadget!(),
            vec_unpack_stage_2: build_opcode_gadget!(),
            write_ref_stage1: build_opcode_gadget!(),
            write_ref_stage2: build_opcode_gadget!(),
            write_ref_stage3: build_opcode_gadget!(),
            nop: build_opcode_gadget!(),
            stop: build_opcode_gadget!(),
            columns: cell_columns,
            step: step_curr,
            challenges,
            stored_expressions_map,
            dynamic_cell_stat_map: additional_cell_stat_map,
            instances,
        };

        Self::configure_opcode_gadget(
            meta,
            &mut config.columns,
            &challenge_exprs,
            &config.step,
            config.s_usable,
            config.s_step_first,
            config.s_step_last,
            lookup_table_configs,
            constraints_map,
            lookup_map,
        );

        Self::configure_lookup(
            meta,
            &config.columns,
            &challenge_exprs,
            lookup_table_configs,
            &config.step,
            s_usable,
        );

        Self::configure_shuffle(meta, &config.step, s_usable);

        if used_execution_states.contains(&ExecutionState::CallStage1)
            && used_execution_states.contains(&ExecutionState::Ret)
        {
            Self::configure_callstack(meta, &config, s_usable, &config.step);
        }

        config
    }

    fn build_opcode_gadget<G: InstructionGadgetV2<F>>(
        meta: &mut ConstraintSystem<F>,
        columns: &mut CellManagerColumns,
        challenges: &Challenges<Expression<F>>,
        step_curr: &Step<F>,
        constraints_map: &mut BTreeMap<Option<ExecutionState>, Constraints<F>>,
        stored_expressions_map: &mut BTreeMap<Option<ExecutionState>, StoredExpressions<F>>,
        lookup_map: &mut BTreeMap<Option<ExecutionState>, Lookups<F>>,
        cell_stat_map: &mut BTreeMap<ExecutionState, BTreeMap<CellType, usize>>, // TODO: replace with Instrument
        used_execution_states: &[ExecutionState],
    ) -> Option<Box<G>> {
        if used_execution_states.contains(&G::EXECUTION_STATE) {
            // Now actually configure the gadget with the correct minimal height
            let mut cb = ConstraintBuilderV2::new(
                meta,
                columns,
                challenges,
                step_curr.clone(),
                Some(G::EXECUTION_STATE),
            );
            let gadget = G::configure(&mut cb);

            let mut stat = cb.curr.cell_manager.get_stats(cb.columns);
            debug_assert_eq!(stat.len(), 1);
            cell_stat_map.insert(G::EXECUTION_STATE, stat.pop().unwrap());

            let (_, constraints, lookups, stored_expressions, _meta, _columns) = cb.build();

            constraints_map.insert(Some(G::EXECUTION_STATE), constraints);
            lookup_map.insert(Some(G::EXECUTION_STATE), lookups);
            stored_expressions_map.insert(Some(G::EXECUTION_STATE), stored_expressions);

            Some(Box::new(gadget))
        } else {
            None
        }
    }
    fn configure_opcode_gadget(
        meta: &mut ConstraintSystem<F>,
        columns: &mut CellManagerColumns,
        challenges: &Challenges<Expression<F>>,
        step_curr: &Step<F>,
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        lookup_table_config: &LookupTableConfigV2<F>,
        constraints_map: BTreeMap<Option<ExecutionState>, Constraints<F>>,
        lookup_map: BTreeMap<Option<ExecutionState>, Lookups<F>>,
    ) {
        let step_prev = Step::new(meta, columns, -1, challenges).state;
        let step_next = Step::new(meta, columns, 1, challenges).state;

        // Enforce the logic for this opcode
        let first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first);
            util::or::expr([
                row0,
                step_curr.state.clk.expr() - step_prev.clk.expr(), /* = 1 */
            ])
        };

        let last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last);
            util::or::expr([
                row_n,
                step_next.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
            ])
        };
        let not_first_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row0 = meta.query_selector(s_step_first);
            util::and::expr([
                util::not::expr(row0),
                util::not::expr(
                    step_curr.state.clk.expr() - step_prev.clk.expr(), /* = 1 */
                ),
            ])
        };
        let not_last_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            let row_n = meta.query_selector(s_step_last);
            util::and::expr([
                util::not::expr(row_n),
                util::not::expr(
                    step_next.clk.expr() - step_curr.state.clk.expr(), /* = 1 */
                ),
            ])
        };
        let any_row: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|_| 1.expr();

        for (state, mut constraints) in constraints_map {
            let constraint_len: usize = constraints.values().map(|c| c.len()).sum();
            if constraint_len > 0 {
                meta.create_gate(
                    state
                        .map(|s| format!("{:?}", s))
                        .unwrap_or("base constraints".to_string()),
                    move |meta| {
                        let q_usable = meta.query_selector(s_usable);

                        let row_selectors: Vec<_> = [
                            (any_row, None),
                            (first_row, Some(ConstraintLocation::FirstRow)),
                            (last_row, Some(ConstraintLocation::LastRow)),
                            (not_first_row, Some(ConstraintLocation::NotFirstRow)),
                            (not_last_row, Some(ConstraintLocation::NotLastRow)),
                        ]
                        .into_iter()
                        .map(|(selector, l)| (selector(meta), l))
                        .collect();
                        let state_selector = match state {
                            Some(s) => step_curr.execution_state_selector([s]),
                            None => 1.expr(),
                        };

                        row_selectors.into_iter().flat_map(
                            move |(row_selector, constraint_location)| {
                                let q_usable = q_usable.clone();
                                let state_selector = state_selector.clone();

                                constraints
                                    .remove(&constraint_location)
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map({
                                        move |(name, constraint)| {
                                            (
                                                name,
                                                q_usable.clone()
                                                    * state_selector.clone()
                                                    * row_selector.clone()
                                                    * constraint,
                                            )
                                        }
                                    })
                            },
                        )
                    },
                );
            }
        }

        for (state, lookups) in lookup_map {
            let state_selector = match state {
                Some(s) => step_curr.execution_state_selector([s]),
                None => 1.expr(),
            };

            for (selector, constraint_location) in [
                (first_row, Some(ConstraintLocation::FirstRow)),
                (last_row, Some(ConstraintLocation::LastRow)),
                (not_first_row, Some(ConstraintLocation::NotFirstRow)),
                (not_last_row, Some(ConstraintLocation::NotLastRow)),
                (any_row, None),
            ] {
                let lookups = lookups.get(&constraint_location);
                if let Some(lookups) = lookups {
                    for (name, lookup) in lookups {
                        meta.lookup_any(name.as_str(), |meta| {
                            let s_usable = meta.query_selector(s_usable);
                            let row_selector = selector(meta);

                            let table_expressions =
                                lookup_table_config.table_exprs(lookup.table(), meta);
                            lookup
                                .input_exprs()
                                .into_iter()
                                .map(|e| {
                                    s_usable.clone()
                                        * row_selector.clone()
                                        * state_selector.clone()
                                        * e
                                })
                                .zip(table_expressions)
                                .collect()
                        });
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_lookup(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &CellManagerColumns,
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
                step_curr.state.operand0.expr(),
                step_curr.state.operand1.expr(),
            ]
            .into_iter()
            .map(|e| s_usable.clone() * e)
            .zip(table_expressions)
            .collect()
        });
        for column in cell_manager_columns.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                let name = format!("{:?}", table);
                let column_expr = column.expr(meta);
                meta.lookup_any(name.as_str(), |meta| {
                    let s_usable = meta.query_selector(s_usable);
                    let table_expressions = lookup_table_config.table_exprs(table, meta);
                    vec![(
                        s_usable * column_expr,
                        rlc::expr(&table_expressions, challenges.lookup_input()),
                    )]
                });
            }
        }
    }

    fn configure_shuffle(meta: &mut ConstraintSystem<F>, step_curr: &Step<F>, s_usable: Selector) {
        meta.shuffle("stack consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let pop_version = step_curr.state.stack_pop_version.expr();
            // NOTICE: version is also used as a selector to exclude empty operations
            let pop_set = [
                step_curr.state.stack_pop_index.expr(),
                step_curr.state.stack_pop_sub_index.expr(),
                step_curr.state.stack_pop_value_header.expr(),
                pop_version.clone(),
            ]
            .into_iter()
            .chain(step_curr.state.stack_pop_value.exprs())
            .map(|e| s_usable.clone() * pop_version.clone() * e);
            let push_version = step_curr.state.stack_push_version.expr();
            let push_set = [
                step_curr.state.stack_push_index.expr(),
                step_curr.state.stack_push_sub_index.expr(),
                step_curr.state.stack_push_value_header.expr(),
                push_version.clone(),
            ]
            .into_iter()
            .chain(step_curr.state.stack_push_value.exprs())
            .map(|e| s_usable.clone() * push_version.clone() * e);
            pop_set.zip(push_set).collect()
        });
        meta.shuffle("local consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let read_version = step_curr.state.local_read_version.expr();
            let read_set = [
                step_curr.state.local_frame_index.expr(),
                step_curr.state.local_index.expr(),
                step_curr.state.local_sub_index.expr(),
                step_curr.state.local_read_value_header.expr(),
                step_curr.state.local_read_value_invalid.expr(),
                read_version.clone(),
            ]
            .into_iter()
            .chain(step_curr.state.local_read_value.exprs())
            .map(|e| s_usable.clone() * read_version.clone() * e);
            let write_version = step_curr.state.local_write_version.expr();
            let write_set = [
                step_curr.state.local_frame_index.expr(),
                step_curr.state.local_index.expr(),
                step_curr.state.local_sub_index.expr(),
                step_curr.state.local_write_value_header.expr(),
                step_curr.state.local_write_value_invalid.expr(),
                write_version.clone(),
            ]
            .into_iter()
            .chain(step_curr.state.local_write_value.exprs())
            .map(|e| s_usable.clone() * write_version.clone() * e);
            read_set.zip(write_set).collect()
        });
    }

    fn configure_callstack(
        meta: &mut ConstraintSystem<F>,
        config: &ExecutionConfig<F>,
        s_usable: Selector,
        step_curr: &Step<F>,
    ) {
        let s_callstack_push = step_curr.execution_state_selector([ExecutionState::CallStage1]);
        let s_callstack_pop = step_curr.execution_state_selector([ExecutionState::Ret]);
        meta.shuffle("callstack consistency check", |meta| {
            let s_usable = meta.query_selector(s_usable);
            let call_stage_1 = config
                .call_stage_1
                .as_ref()
                .expect("CallStage1 gadget must be configured");
            let ret = config.ret.as_ref().expect("Ret gadget must be configured");
            let input_exprs = call_stage_1
                .call_context
                .exprs()
                .into_iter()
                .map(|e| s_usable.clone() * s_callstack_push.clone() * e);
            let shuffled_exprs = ret
                .call_context
                .exprs()
                .into_iter()
                .map(|e| s_usable.clone() * s_callstack_pop.clone() * e);
            input_exprs.into_iter().zip(shuffled_exprs).collect()
        });
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        states: Vec<StageState>,
        static_info: &StaticInfo,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "execution region",
            |mut region| {
                let mut offset = 0;
                self.s_step_first.enable(&mut region, offset)?;
                {
                    // we need to cache the whole assignment,
                    // or else, we cannot access cached data in region of previous stage
                    // as they're different regions.
                    let mut cached_region = CachedRegion::<'_, '_, F>::new(
                        &mut region,
                        challenges,
                        self.columns.columns().iter().map(|c| c.advice).collect(),
                        states.iter().map(|s| s.rows()).sum(),
                        offset,
                    );
                    for opcode_witness in &states {
                        let step_rows = self.assign_exec_step(
                            &mut cached_region,
                            offset,
                            opcode_witness,
                            static_info,
                            &self.instances,
                        )?;
                        for row in offset..offset + step_rows {
                            self.s_usable.enable(cached_region.region(), row)?;
                        }
                        offset += step_rows;
                    }

                    // had to assign stored_expression later,
                    // as it may reference next rows.
                    let mut offset = 0;
                    for opcode_witness in &states {
                        let step_rows = opcode_witness.rows();
                        self.assign_stored_expression(&mut cached_region, offset, opcode_witness)?;
                        offset += step_rows;
                    }
                }
                self.s_step_last.enable(&mut region, offset - 1)?;
                Ok(())
            },
        )?;

        Ok(())
    }
    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset_begin: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
        instances: &InstanceTable,
    ) -> Result<usize, Error> {
        macro_rules! assign_exec_step {
            ($state:expr,{$($exec_state:pat=>$gadget_field:expr),*$(,)?}) => {
                match $state {
                    $($exec_state=> {
                        let gadget = $gadget_field.as_ref().ok_or_else(|| Error::Synthesis)?;
                        gadget.assign_common(self.base_constraint.as_ref(), &self.step.state, region, offset_begin, stage_state, static_info)?;
                        gadget.assign(self.step.state.clone(), region, offset_begin, stage_state, static_info, instances)?
                    },)*
                    s => unreachable!("unsupported execution state {:?}", &s)
                }
            };
        }
        let assigned_rows = assign_exec_step!(stage_state.step_states.first().unwrap().step_state.exec_state, {
            ExecutionState::VecLen => self.vec_len,
            ExecutionState::VecPack => self.vec_pack,
            ExecutionState::VecUnpackStage1 => self.vec_unpack_stage_1,
            ExecutionState::VecUnpackStage2 => self.vec_unpack_stage_2,
            ExecutionState::StoreLocStage1 => self.store_loc_stage1,
            ExecutionState::StoreLocStage2 => self.store_loc_stage2,
            ExecutionState::VecPopBackStage1 => self.vec_pop_back_stage1,
            ExecutionState::VecPopBackStage2 => self.vec_pop_back_stage2,
            ExecutionState::VecPushBackStage1 => self.vec_push_back_stage1,
            ExecutionState::VecPushBackStage2 => self.vec_push_back_stage2,
            ExecutionState::VecSwapStage1 => self.vec_swap_stage_1,
            ExecutionState::VecSwapStage2 => self.vec_swap_stage_2,
            ExecutionState::VecSwapStage3 => self.vec_swap_stage_3,
            ExecutionState::VecSwapStage4 => self.vec_swap_stage_4,
            ExecutionState::VecSwapStage5 => self.vec_swap_stage_5,
            ExecutionState::AddSub => self.add_sub,
            ExecutionState::AndOr => self.and_or,
            ExecutionState::BitwiseStage1 => self.bitwise_stage1,
            ExecutionState::BitwiseStage2 => self.bitwise_stage2,
            ExecutionState::BorrowField => self.borrow_field,
            ExecutionState::BorrowLoc => self.borrow_loc,
            ExecutionState::BrTrue => self.br_true,
            ExecutionState::BrFalse => self.br_false,
            ExecutionState::Branch => self.branch,
            ExecutionState::CallStage1 => self.call_stage_1,
            ExecutionState::CallStage2 => self.call_stage_2,
            ExecutionState::CallStage3 => self.call_stage_3,
            ExecutionState::Cast => self.cast,
            ExecutionState::EqStage1 => self.eq_stage_1,
            ExecutionState::EqStage2 => self.eq_stage_2,
            ExecutionState::NeqStage1 => self.neq_stage_1,
            ExecutionState::NeqStage2 => self.neq_stage_2,
            ExecutionState::Ge => self.ge,
            ExecutionState::Gt => self.gt,
            ExecutionState::LdFalse => self.ld_false,
            ExecutionState::LdTrue => self.ld_true,
            ExecutionState::LdConst => self.ld_const,
            ExecutionState::LdSimple => self.ld_simple,
            ExecutionState::Le => self.le,
            ExecutionState::Lt => self.lt,
            ExecutionState::MoveLoc => self.move_loc,
            ExecutionState::CopyLoc => self.copy_loc,
            ExecutionState::MulDivModStage1 => self.mul_div_mod_stage1,
            ExecutionState::MulDivModStage2=> self.mul_div_mod_stage2,
            ExecutionState::Not => self.not,
            ExecutionState::Nop => self.nop,
            ExecutionState::Pack => self.pack,
            ExecutionState::Pop => self.pop,
            ExecutionState::ReadRef => self.read_ref,
            ExecutionState::Ret => self.ret,
            ExecutionState::UnpackStage1 => self.unpack_stage_1,
            ExecutionState::UnpackStage2 => self.unpack_stage_2,
            ExecutionState::VecBorrow => self.vec_borrow,
            ExecutionState::WriteRefStage1 => self.write_ref_stage1,
            ExecutionState::WriteRefStage2 => self.write_ref_stage2,
            ExecutionState::WriteRefStage3 => self.write_ref_stage3,
            ExecutionState::Teardown => self.teardown,
            ExecutionState::Abort => self.abort,
            ExecutionState::ErrorState => self.error,
            ExecutionState::Start => self.start,
            ExecutionState::ProcessArg => self.process_arg,
            ExecutionState::ShiftStage1 => self.shift_stage1,
            ExecutionState::ShiftStage2 => self.shift_stage2,
            ExecutionState::Stop => self.stop,
            ExecutionState::NativePoseidonHash => self.native_poseidon_hash,
        });
        debug_assert_eq!(assigned_rows, stage_state.rows());
        Ok(assigned_rows)
    }

    fn assign_stored_expression(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset_begin: usize,
        stage_state: &StageState,
    ) -> Result<(), Error> {
        let stored_expressions_map = &self.stored_expressions_map;
        debug_assert!(!stage_state.step_states.is_empty());
        let execution_state = &stage_state
            .step_states
            .first()
            .unwrap()
            .step_state
            .exec_state;
        let rows = stage_state.rows();
        for i in 0..rows {
            let is_first_row = i == 0;
            let is_last_row = i == rows - 1;

            if let Some(stored_expressions) = stored_expressions_map.get(&Some(*execution_state)) {
                for (location, expressions) in stored_expressions {
                    let row_match = match location {
                        Some(ConstraintLocation::FirstRow) => is_first_row,
                        Some(ConstraintLocation::LastRow) => is_last_row,
                        Some(ConstraintLocation::NotFirstRow) => !is_first_row,
                        Some(ConstraintLocation::NotLastRow) => !is_last_row,
                        None => true,
                    };

                    for expression in expressions {
                        if row_match {
                            expression.assign(region, offset_begin + i)?;
                        } else {
                            expression.assign_empty(region, offset_begin + i)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub(crate) trait InstructionGadgetV2<F: Field> {
    const NAME: &'static str;

    const OPCODES: &'static [Opcodes] = Self::EXECUTION_STATE.responsible_opcodes();
    const EXECUTION_STATE: ExecutionState;
    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self;
    fn assign_common(
        &self,
        base_constraint_gadget: &BaseConstraintGadget<F>,
        step_state: &StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset_begin: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        assign_step_and_common(
            base_constraint_gadget,
            step_state,
            region,
            offset_begin,
            stage_state,
            static_info,
        )
    }

    fn assign(
        &self,
        _step_state: StepState<F>,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        stage_state: &StageState,
        _static_info: &StaticInfo,
        _instances: &InstanceTable,
    ) -> Result<usize, Error> {
        Ok(stage_state.rows())
    }
}

pub(crate) fn assign_step_and_common<F: Field>(
    base_constraint_gadget: &BaseConstraintGadget<F>,
    step_state: &StepState<F>,
    region: &mut CachedRegion<'_, '_, F>,
    offset_begin: usize,
    stage_state: &StageState,
    _static_info: &StaticInfo,
) -> Result<usize, Error> {
    debug_assert!(!stage_state.step_states.is_empty());

    let mut step_counter = stage_state.rows();
    let mut i = 0;
    for exec_step_state in &stage_state.step_states {
        for memory_op in exec_step_state.memory_ops.iter() {
            step_state.assign_exec_step(
                region,
                offset_begin + i,
                step_counter,
                &exec_step_state.step_state,
                memory_op,
            )?;
            base_constraint_gadget.assign(step_state.clone(), region, offset_begin + i)?;
            i += 1;
            step_counter -= 1;
        }
    }
    Ok(stage_state.rows())
}
