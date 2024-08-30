use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::utils::base_constraint_builder::{
    BaseConstraintBuilder, ConstrainBuilderCommon,
};
use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::execution_chip_v2::executions::nop::Nop;
use crate::chips::execution_chip_v2::executions::BaseConstraintGadget;
use crate::chips::execution_chip_v2::executions::{
    AddSub, AndOr, Bitwise, BorrowField, BorrowLoc, BrBool, CallStage1, CallStage2, CallStage3,
    Cast, Equality, ExecutionState, LdBool, LdConst, LdSimple, Le, Lt, MoveOrCopyLoc, MulDivMod,
    Not, Pack, Pop, ReadRef, Ret, StoreLocStage1, StoreLocStage2, UnpackStage1, UnpackStage2,
    VecBorrow, VecLen, VecPopBackStage1, VecPopBackStage2, VecPushBackStage1, VecPushBackStage2,
    VecSwapStage_1, VecSwapStage_2_Or_3, VecSwapStage_4_Or_5, WriteRefStage1, WriteRefStage2,
    WriteRefStage3,
};
use crate::chips::execution_chip_v2::lookup_table::{LookupTableConfigV2, Table};
use crate::chips::execution_chip_v2::step_v2::{Step, StepState};
use crate::chips::utilities::Expr;
use crate::table::LookupTable;
use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{CellManagerColumns, CellType};
use crate::utils::challenges::Challenges;
use crate::utils::rlc;
use crate::utils::SubCircuitConfig;
use crate::witness::WitnessV2;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::step_state::StageState;
use gadgets::util::{and, not, or};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, Selector, VirtualCells};
use std::iter;
use types::Field;

pub(crate) mod call_stack;
pub(crate) mod executions;
pub(crate) mod lookup_table;
pub(crate) mod math_gadgets;
pub(crate) mod step_v2;
pub(crate) mod sub_index;
pub(crate) mod utils;
pub(crate) mod value;

#[derive(Clone)]
pub(crate) struct ExecChipConfig<F> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub s_step_last: Selector,
    pub columns: CellManagerColumns,
    pub base_constraint: Box<BaseConstraintGadget<F>>,
    pub add_sub: Box<AddSub<F>>,
    pub and_or: Box<AndOr<F>>,
    pub bitwise: Box<Bitwise<F>>,
    pub borrow_field: Box<BorrowField<F>>,
    pub borrow_loc: Box<BorrowLoc<F>>,
    pub br_true: Box<BrBool<F, true>>,
    pub br_false: Box<BrBool<F, false>>,
    pub call_stage_1: Box<CallStage1<F>>,
    pub call_stage_2: Box<CallStage2<F>>,
    pub call_stage_3: Box<CallStage3<F>>,
    pub cast: Box<Cast<F>>,
    pub copy_loc: Box<MoveOrCopyLoc<F, false>>,
    pub eq_stage_1: Box<Equality<F, true, true>>,
    pub eq_stage_2: Box<Equality<F, false, true>>,
    pub ge: Box<Lt<F, false>>,
    pub gt: Box<Le<F, false>>,
    pub ld_simple: Box<LdSimple<F>>,
    pub ld_true: Box<LdBool<F, true>>,
    pub ld_false: Box<LdBool<F, false>>,
    pub ld_const: Box<LdConst<F>>,
    pub le: Box<Le<F, true>>,
    pub lt: Box<Lt<F, true>>,
    pub move_loc: Box<MoveOrCopyLoc<F, true>>,
    pub mul_div_mod: Box<MulDivMod<F>>,
    pub neq_stage_1: Box<Equality<F, true, false>>,
    pub neq_stage_2: Box<Equality<F, false, false>>,
    pub not: Box<Not<F>>,
    pub pack: Box<Pack<F, false>>,
    pub pop: Box<Pop<F>>,
    pub read_ref: Box<ReadRef<F>>,
    pub ret: Box<Ret<F>>,
    pub store_loc_stage1: Box<StoreLocStage1<F>>,
    pub store_loc_stage2: Box<StoreLocStage2<F>>,
    pub unpack_stage_1: Box<UnpackStage1<F, false>>,
    pub unpack_stage_2: Box<UnpackStage2<F, false>>,
    pub vec_borrow: Box<VecBorrow<F>>,
    pub vec_len: Box<VecLen<F>>,
    pub vec_pack: Box<Pack<F, true>>,
    pub vec_pop_back_stage1: Box<VecPopBackStage1<F>>,
    pub vec_pop_back_stage2: Box<VecPopBackStage2<F>>,
    pub vec_push_back_stage1: Box<VecPushBackStage1<F>>,
    pub vec_push_back_stage2: Box<VecPushBackStage2<F>>,
    pub vec_swap_stage_1: Box<VecSwapStage_1<F>>,
    pub vec_swap_stage_2: Box<VecSwapStage_2_Or_3<F, true>>,
    pub vec_swap_stage_3: Box<VecSwapStage_2_Or_3<F, false>>,
    pub vec_swap_stage_4: Box<VecSwapStage_4_Or_5<F, true>>,
    pub vec_swap_stage_5: Box<VecSwapStage_4_Or_5<F, false>>,
    pub vec_unpack_stage_1: Box<UnpackStage1<F, true>>,
    pub vec_unpack_stage_2: Box<UnpackStage2<F, true>>,
    pub write_ref_stage1: Box<WriteRefStage1<F>>,
    pub write_ref_stage2: Box<WriteRefStage2<F>>,
    pub write_ref_stage3: Box<WriteRefStage3<F>>,
    pub nop: Box<Nop<F>>,
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
        let mut cell_columns = CellManagerColumns::default();
        let step_curr = Step::new(meta, &mut cell_columns, 0, &challenges);
        let step_next = Step::new(meta, &mut cell_columns, 1, &challenges);
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
                cb.require_zero("first step, pc = 0", step_curr.state.pc.expr());
                cb.require_zero(
                    "first step, frame_index = 0",
                    step_curr.state.frame_index.expr(),
                );
                //TODO: require module_index/function_index equal to entry_module/entry_func

                // cb.require_zero(
                //     "first step, module_index = 0",
                //     step_curr.cells.module_index.expr(),
                // );
                // cb.require_zero(
                //     "first step, function_index = 0",
                //     step_curr.state.function_index.expr(),
                // );
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
                let end_opcode_selector = step_curr.execution_state_selector([ExecutionState::Nop]);
                iter::once((
                    "Last step should be Nop",
                    s_step_last * (1u64.expr() - end_opcode_selector),
                ))
            };

            execution_state_selector_constraints
                .into_iter()
                .map(move |(name, poly)| (name, s_usable.clone() * poly))
            // FIXME
            // .chain(first_step_check)
            // .chain(last_step_check)
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
        let (step_curr, base_constraint) = {
            let mut cb =
                ConstraintBuilderV2::new(meta, &mut cell_columns, &challenges, step_curr, None);
            let base_constraint = BaseConstraintGadget::configure(&mut cb);
            // we need to reuse the step_curr when configuring opcode gadgets.
            let step_curr = cb.curr.clone();
            Self::configure_opcode_gadget_impl(
                s_usable,
                s_step_first,
                s_step_last,
                "base constraints",
                cb,
            );
            (step_curr, base_constraint)
        };
        macro_rules! configure_opcode_gadget {
            () => {
                Box::new(Self::configure_opcode_gadget(
                    meta,
                    &mut cell_columns,
                    &challenges,
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
            s_step_last,
            base_constraint: Box::new(base_constraint),
            add_sub: configure_opcode_gadget!(),
            and_or: configure_opcode_gadget!(),
            bitwise: configure_opcode_gadget!(),
            borrow_field: configure_opcode_gadget!(),
            borrow_loc: configure_opcode_gadget!(),
            br_true: configure_opcode_gadget!(),
            br_false: configure_opcode_gadget!(),
            call_stage_1: configure_opcode_gadget!(),
            call_stage_2: configure_opcode_gadget!(),
            call_stage_3: configure_opcode_gadget!(),
            cast: configure_opcode_gadget!(),
            copy_loc: configure_opcode_gadget!(),
            eq_stage_1: configure_opcode_gadget!(),
            eq_stage_2: configure_opcode_gadget!(),
            ge: configure_opcode_gadget!(),
            gt: configure_opcode_gadget!(),
            ld_simple: configure_opcode_gadget!(),
            ld_true: configure_opcode_gadget!(),
            ld_false: configure_opcode_gadget!(),
            ld_const: configure_opcode_gadget!(),
            le: configure_opcode_gadget!(),
            lt: configure_opcode_gadget!(),
            move_loc: configure_opcode_gadget!(),
            mul_div_mod: configure_opcode_gadget!(),
            neq_stage_1: configure_opcode_gadget!(),
            neq_stage_2: configure_opcode_gadget!(),
            not: configure_opcode_gadget!(),
            pack: configure_opcode_gadget!(),
            pop: configure_opcode_gadget!(),
            read_ref: configure_opcode_gadget!(),
            ret: configure_opcode_gadget!(),
            store_loc_stage1: configure_opcode_gadget!(),
            store_loc_stage2: configure_opcode_gadget!(),
            unpack_stage_1: configure_opcode_gadget!(),
            unpack_stage_2: configure_opcode_gadget!(),
            vec_borrow: configure_opcode_gadget!(),
            vec_len: configure_opcode_gadget!(),
            vec_pack: configure_opcode_gadget!(),
            vec_pop_back_stage1: configure_opcode_gadget!(),
            vec_pop_back_stage2: configure_opcode_gadget!(),
            vec_push_back_stage1: configure_opcode_gadget!(),
            vec_push_back_stage2: configure_opcode_gadget!(),
            vec_swap_stage_1: configure_opcode_gadget!(),
            vec_swap_stage_2: configure_opcode_gadget!(),
            vec_swap_stage_3: configure_opcode_gadget!(),
            vec_swap_stage_4: configure_opcode_gadget!(),
            vec_swap_stage_5: configure_opcode_gadget!(),
            vec_unpack_stage_1: configure_opcode_gadget!(),
            vec_unpack_stage_2: configure_opcode_gadget!(),
            write_ref_stage1: configure_opcode_gadget!(),
            write_ref_stage2: configure_opcode_gadget!(),
            write_ref_stage3: configure_opcode_gadget!(),
            nop: configure_opcode_gadget!(),
            columns: cell_columns,
            step: step_curr,
        };
        Self::configure_lookup(
            meta,
            &config.columns,
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
        columns: &mut CellManagerColumns,
        challenges: &Challenges<Expression<F>>,
        //lookups: &mut Vec<(&'static str, ConditionalLookup<F>)>,
        s_usable: Selector,
        s_step_first: Selector,
        s_step_last: Selector,
        //s_step: Column<Advice>,
        step_curr: &Step<F>,
    ) -> G {
        // Now actually configure the gadget with the correct minimal height
        let mut cb = ConstraintBuilderV2::new(
            meta,
            columns,
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
                step_curr.state.aux0.expr(),
                step_curr.state.aux1.expr(),
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
                    let table_expressions = match table {
                        Table::Nibble => lookup_table_config.nibble_table.table_exprs(meta),
                        Table::U8 => lookup_table_config.u8_table.table_exprs(meta),
                        Table::U16 => lookup_table_config.u16_table.table_exprs(meta),
                        Table::Function => lookup_table_config.function_table.table_exprs(meta),
                        Table::Bitwise => lookup_table_config.bitwise_table.table_exprs(meta),
                        Table::Bytecode => lookup_table_config.bytecode_table.table_exprs(meta),
                        Table::Constant => lookup_table_config.constant_table.table_exprs(meta),
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

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &WitnessV2,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "execution region",
            |mut region| {
                let mut offset = 0;
                self.s_step_first.enable(&mut region, offset)?;
                for opcode_witness in &witness.opcode_witnesses {
                    offset += self.assign_exec_step(
                        &mut region,
                        offset,
                        opcode_witness,
                        challenges,
                        &witness.static_info,
                    )?;
                }
                self.s_step_last.enable(&mut region, offset - 1)?;
                Ok(())
            },
        )?;

        Ok(())
    }
    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset_begin: usize,
        stage_state: &StageState,
        challenges: &Challenges<Value<F>>,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        debug_assert!(!stage_state.step_states.is_empty());

        let region = &mut CachedRegion::<'_, '_, F>::new(
            region,
            challenges,
            self.columns.columns().iter().map(|c| c.advice).collect(),
            stage_state.rows(),
            offset_begin,
        );
        let mut step_counter = stage_state.rows();
        let mut i = 0;
        for exec_step_state in &stage_state.step_states {
            for memory_op in exec_step_state.memory_ops.iter() {
                self.s_usable.enable(region.region(), offset_begin + i)?;
                self.step.assign_exec_step(
                    region,
                    offset_begin + i,
                    step_counter,
                    &exec_step_state.step_state,
                    memory_op,
                )?;
                self.base_constraint.assign(
                    self.step.state.clone(),
                    region,
                    offset_begin + i,
                    stage_state,
                    static_info,
                )?;
                i += 1;
                step_counter -= 1;
            }
        }

        macro_rules! assign_exec_step {
            ($state:expr,{$($exec_state:pat=>$gadget_field:expr),*$(,)?}) => {
                match $state {
                    $(($exec_state)=>$gadget_field.assign(self.step.state.clone(), region, offset_begin, stage_state, static_info),)*
                    _=>unimplemented!()
                }
            };
        }
        let assigned_rows = assign_exec_step!(stage_state.step_states.first().unwrap().step_state.exec_state, {
        ExecutionState::VecLen => self.vec_len,
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
        ExecutionState::Bitwise => self.bitwise,
        ExecutionState::BorrowField => self.borrow_field,
        ExecutionState::BorrowLoc => self.borrow_loc,
        ExecutionState::BrTrue => self.br_true,
        ExecutionState::BrFalse => self.br_false,
        ExecutionState::CallStage1 => self.call_stage_1,
        ExecutionState::CallStage2 => self.call_stage_2,
        ExecutionState::CallStage3 => self.call_stage_3,
        ExecutionState::Cast => self.cast,
        ExecutionState::EqStage1 => self.eq_stage_1,
        ExecutionState::EqStage2 => self.eq_stage_2,
        ExecutionState::LdFalse => self.ld_false,
        ExecutionState::LdTrue => self.ld_true,
        ExecutionState::LdConst => self.ld_const,
        ExecutionState::LdSimple => self.ld_simple,
        ExecutionState::Le => self.le,
        ExecutionState::Lt => self.lt,
        ExecutionState::MoveLoc => self.move_loc,
        ExecutionState::CopyLoc => self.copy_loc,
        ExecutionState::MulDivMod => self.mul_div_mod,
        ExecutionState::Not => self.not,
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
        ExecutionState::Nop => self.nop,
        })?;
        debug_assert_eq!(assigned_rows, stage_state.rows());

        Ok(assigned_rows)
    }
}

pub(crate) trait InstructionGadgetV2<F: Field> {
    const NAME: &'static str;

    const OPCODES: &'static [Opcode];
    const EXECUTION_STATE: ExecutionState;
    fn configure(cb: &mut ConstraintBuilderV2<F>) -> Self;

    fn assign(
        &self,
        step: StepState<F>,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        stage_state: &StageState,
        static_info: &StaticInfo,
    ) -> Result<usize, Error> {
        Ok(stage_state.rows())
    }
}
