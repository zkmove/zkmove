// Copyright (c) zkMove Authors
use crate::chips::execution_chip::instructions::_mod::Mod;
use crate::chips::execution_chip::instructions::abort::Abort;
use crate::chips::execution_chip::instructions::add::Add;
use crate::chips::execution_chip::instructions::and::And;
use crate::chips::execution_chip::instructions::bit_and::BitAnd;
use crate::chips::execution_chip::instructions::bit_or::BitOr;
use crate::chips::execution_chip::instructions::borrow_field::BorrowField;
use crate::chips::execution_chip::instructions::borrow_global::BorrowGlobal;
use crate::chips::execution_chip::instructions::borrow_loc::BorrowLoc;
use crate::chips::execution_chip::instructions::br_false::BrFalse;
use crate::chips::execution_chip::instructions::br_true::BrTrue;
use crate::chips::execution_chip::instructions::branch::Branch;
use crate::chips::execution_chip::instructions::call::Call;
use crate::chips::execution_chip::instructions::castint::CastInt;
use crate::chips::execution_chip::instructions::castu256::CastU256;
use crate::chips::execution_chip::instructions::copy_loc::CopyLoc;
use crate::chips::execution_chip::instructions::div::Div;
use crate::chips::execution_chip::instructions::equality::Equality;
use crate::chips::execution_chip::instructions::exists::Exists;
use crate::chips::execution_chip::instructions::freeze_ref::FreezeRef;
use crate::chips::execution_chip::instructions::ge::Ge;
use crate::chips::execution_chip::instructions::gt::Gt;
use crate::chips::execution_chip::instructions::ld_const::LdConst;
use crate::chips::execution_chip::instructions::ld_false::LdFalse;
use crate::chips::execution_chip::instructions::ld_true::LdTrue;
use crate::chips::execution_chip::instructions::ldint::LdInt;
use crate::chips::execution_chip::instructions::ldu256::LdU256;
use crate::chips::execution_chip::instructions::le::Le;
use crate::chips::execution_chip::instructions::lt::Lt;
use crate::chips::execution_chip::instructions::move_from::MoveFrom;
use crate::chips::execution_chip::instructions::move_loc::MoveLoc;
use crate::chips::execution_chip::instructions::move_to::MoveTo;
use crate::chips::execution_chip::instructions::mul::Mul;
use crate::chips::execution_chip::instructions::nop::Nop;
use crate::chips::execution_chip::instructions::not::Not;
use crate::chips::execution_chip::instructions::or::Or;
use crate::chips::execution_chip::instructions::pack::Pack;
use crate::chips::execution_chip::instructions::pop::Pop;
use crate::chips::execution_chip::instructions::read_ref::ReadRef;
use crate::chips::execution_chip::instructions::ret::Ret;
use crate::chips::execution_chip::instructions::shl::Shl;
use crate::chips::execution_chip::instructions::shr::Shr;
use crate::chips::execution_chip::instructions::st_loc::StLoc;
use crate::chips::execution_chip::instructions::stop::Stop;
use crate::chips::execution_chip::instructions::sub::Sub;
use crate::chips::execution_chip::instructions::unpack::Unpack;
use crate::chips::execution_chip::instructions::vec_borrow::VecBorrow;
use crate::chips::execution_chip::instructions::vec_len::VecLen;
use crate::chips::execution_chip::instructions::vec_pack::VecPack;
use crate::chips::execution_chip::instructions::vec_pop_back::VecPopBack;
use crate::chips::execution_chip::instructions::vec_push_back::VecPushBack;
use crate::chips::execution_chip::instructions::vec_swap::VecSwap;
use crate::chips::execution_chip::instructions::vec_unpack::VecUnpack;
use crate::chips::execution_chip::instructions::write_ref::WriteRef;
use crate::chips::execution_chip::instructions::xor::Xor;
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupTableConfig;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::chips::execution_chip::step_chip::{StepChip, StepChipCells, StepConfig};
use crate::chips::execution_chip::utils::base_constraint_builder::BaseConstraintBuilder;
use crate::chips::execution_chip::utils::constraint_builder::{
    ConditionalLookup, ConstraintBuilder,
};
use crate::chips::utilities::Expr;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::rw_operations::RWOperations;
use crate::witness::Witness;
use halo2_proofs::circuit::{AssignedCell, Chip, Region, Value};
use halo2_proofs::plonk::Constraints;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
};
use logger::{error, trace};
use movelang::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use std::collections::HashMap;

pub mod instructions;
pub mod lookup_tables;
pub mod opcode;
pub mod param;
pub mod step_chip;
pub mod utils;

#[derive(Clone, Debug)]
pub struct ExecutionChipConfig<F: FieldExt> {
    pub s_usable: Selector,
    pub s_step_first: Selector,
    pub s_step: Column<Advice>,
    pub num_rows_until_next_step: Column<Advice>,
    pub num_rows_inv: Column<Advice>,
    step: StepConfig<F>,
    pub(crate) height_map: HashMap<Opcode, usize>,

    // opcode gadget
    op_ldu8: Box<LdInt<F, NUM_OF_BYTES_U8>>,
    op_ldu16: Box<LdInt<F, NUM_OF_BYTES_U16>>,
    op_ldu32: Box<LdInt<F, NUM_OF_BYTES_U32>>,
    op_ldu64: Box<LdInt<F, NUM_OF_BYTES_U64>>,
    op_ldu128: Box<LdInt<F, NUM_OF_BYTES_U128>>,
    op_ldu256: Box<LdU256<F>>,
    op_ld_const: Box<LdConst<F>>,
    op_castu8: Box<CastInt<F, NUM_OF_BYTES_U8>>,
    op_castu16: Box<CastInt<F, NUM_OF_BYTES_U16>>,
    op_castu32: Box<CastInt<F, NUM_OF_BYTES_U32>>,
    op_castu64: Box<CastInt<F, NUM_OF_BYTES_U64>>,
    op_castu128: Box<CastInt<F, NUM_OF_BYTES_U128>>,
    op_castu256: Box<CastU256<F>>,
    op_pop: Box<Pop<F>>,
    op_ret: Box<Ret<F>>,
    op_add: Box<Add<F>>,
    op_mul: Box<Mul<F>>,
    op_copy_loc: Box<CopyLoc<F>>,
    op_sub: Box<Sub<F>>,
    op_div: Box<Div<F>>,
    op_mod: Box<Mod<F>>,
    op_ld_true: Box<LdTrue<F>>,
    op_ld_false: Box<LdFalse<F>>,
    op_eq: Box<Equality<true, F>>,
    op_neq: Box<Equality<false, F>>,
    op_shl: Box<Shl<F>>,
    op_shr: Box<Shr<F>>,
    op_bit_and: Box<BitAnd<F>>,
    op_bit_or: Box<BitOr<F>>,
    op_xor: Box<Xor<F>>,
    op_and: Box<And<F>>,
    op_or: Box<Or<F>>,
    op_not: Box<Not<F>>,
    op_move_loc: Box<MoveLoc<F>>,
    op_st_loc: Box<StLoc<F>>,
    op_branch: Box<Branch<F>>,
    op_br_true: Box<BrTrue<F>>,
    op_br_false: Box<BrFalse<F>>,
    op_call: Box<Call<false, F>>,
    op_abort: Box<Abort<F>>,
    op_le: Box<Le<F>>,
    op_lt: Box<Lt<F>>,
    op_ge: Box<Ge<F>>,
    op_gt: Box<Gt<F>>,
    op_pack: Box<Pack<false, F>>,
    op_unpack: Box<Unpack<false, F>>,
    op_mut_borrow_loc: Box<BorrowLoc<true, F>>,
    op_imm_borrow_loc: Box<BorrowLoc<false, F>>,
    op_read_ref: Box<ReadRef<F>>,
    op_write_ref: Box<WriteRef<F>>,
    op_freeze_ref: Box<FreezeRef<F>>,
    op_vec_imm_borrow: Box<VecBorrow<false, F>>,
    op_vec_mut_borrow: Box<VecBorrow<true, F>>,
    op_vec_len: Box<VecLen<F>>,
    op_vec_pack: Box<VecPack<F>>,
    op_vec_pop_back: Box<VecPopBack<F>>,
    op_vec_push_back: Box<VecPushBack<F>>,
    op_vec_swap: Box<VecSwap<F>>,
    op_vec_unpack: Box<VecUnpack<F>>,
    op_imm_borrow_field: Box<BorrowField<false, false, F>>,
    op_mut_borrow_field: Box<BorrowField<true, false, F>>,
    op_move_from: Box<MoveFrom<false, F>>,
    op_move_to: Box<MoveTo<false, F>>,
    op_exists: Box<Exists<false, F>>,
    op_imm_borrow_global: Box<BorrowGlobal<false, false, F>>,
    op_mut_borrow_global: Box<BorrowGlobal<true, false, F>>,
    op_call_generic: Box<Call<true, F>>,
    op_imm_borrow_global_generic: Box<BorrowGlobal<false, true, F>>,
    op_mut_borrow_global_generic: Box<BorrowGlobal<true, true, F>>,
    op_move_to_generic: Box<MoveTo<true, F>>,
    op_move_from_generic: Box<MoveFrom<true, F>>,
    op_exists_generic: Box<Exists<true, F>>,
    op_pack_generic: Box<Pack<true, F>>,
    op_unpack_generic: Box<Unpack<true, F>>,
    op_imm_borrow_field_generic: Box<BorrowField<false, true, F>>,
    op_mut_borrow_field_generic: Box<BorrowField<true, true, F>>,

    op_stop: Box<Stop<F>>,
    op_nop: Box<Nop<F>>,

    // lookup table
    lookup_table: LookupTableConfig<F>,
}

#[derive(Clone, Debug)]
pub struct ExecutionChip<F: FieldExt> {
    pub(crate) witness: Witness<F>,
    pub(crate) config: ExecutionChipConfig<F>,
}

impl<F: FieldExt> Chip<F> for ExecutionChip<F> {
    type Config = ExecutionChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ExecutionChip<F> {
    pub fn construct(
        witness: Witness<F>,
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self { witness, config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());

        let s_usable = meta.complex_selector();
        let s_step_first = meta.complex_selector();
        let s_step = meta.advice_column();
        let num_rows_until_next_step = meta.advice_column();
        let num_rows_inv = meta.advice_column();

        let step_curr = StepChip::configure(meta, advices, 0, false);

        {
            meta.create_gate("s_step", |meta| {
                let s_usable = meta.query_selector(s_usable);
                let s_step = meta.query_advice(s_step, Rotation::cur());
                let s_step_first = meta.query_selector(s_step_first);
                let num_rows_left_cur =
                    meta.query_advice(num_rows_until_next_step, Rotation::cur());
                let num_rows_left_next =
                    meta.query_advice(num_rows_until_next_step, Rotation::next());
                let num_rows_left_inverse = meta.query_advice(num_rows_inv, Rotation::cur());
                let mut cb = BaseConstraintBuilder::default();

                // s_step should be enabled on the first row
                cb.condition(s_step_first, |cb| {
                    cb.require_equal("s_step = 1", s_step.clone(), 1.expr());
                    cb.require_zero("first step, pc = 0", step_curr.cells.pc.expr());
                    cb.require_zero(
                        "first step, frame_index = 0",
                        step_curr.cells.frame_index.expr(),
                    );
                    // cb.require_zero(
                    //     "first step, module_index = 0",
                    //     step_curr.cells.module_index.expr(),
                    // );
                    cb.require_zero(
                        "first step, function_index = 0",
                        step_curr.cells.function_index.expr(),
                    );
                });
                // Except when step is enabled, the step counter needs to decrease by 1
                cb.condition(1.expr() - s_step.clone(), |cb| {
                    cb.require_equal(
                        "num_rows_left_cur := num_rows_left_next + 1",
                        num_rows_left_cur.clone(),
                        num_rows_left_next + 1.expr(),
                    );
                });
                // Enforce that s_step := num_rows_until_next_step == 0
                let is_zero =
                    1.expr() - (num_rows_left_cur.clone() * num_rows_left_inverse.clone());
                cb.require_zero(
                    "num_rows_left_cur * is_zero == 0",
                    num_rows_left_cur * is_zero.clone(),
                );
                cb.require_zero(
                    "num_rows_left_inverse * is_zero == 0",
                    num_rows_left_inverse * is_zero.clone(),
                );
                cb.require_equal("s_step == is_zero", s_step, is_zero);

                // On each usable row
                cb.gate(s_usable)
            });
            // config each execution path of the step
            meta.create_gate("constrain execution step", |meta| {
                let s_usable = meta.query_selector(s_usable);
                let s_step = meta.query_advice(s_step, Rotation::cur());
                Constraints::with_selector(
                    s_usable * s_step,
                    step_curr.cells.conditions.configure(),
                )
            });
        }
        let mut height_map = HashMap::new();

        // let mut lookups = LookupsWithCondition::new();
        let mut lookups = Vec::new();
        macro_rules! configure_opcode_gadget {
            () => {
                Box::new(Self::configure_opcode_gadget(
                    meta,
                    &mut lookups,
                    advices,
                    s_usable,
                    s_step,
                    &step_curr,
                    &mut height_map,
                ))
            };
        }

        ExecutionChipConfig {
            s_usable,
            s_step_first,
            s_step,
            num_rows_until_next_step,
            num_rows_inv,
            op_ldu8: configure_opcode_gadget!(),
            op_ldu16: configure_opcode_gadget!(),
            op_ldu32: configure_opcode_gadget!(),
            op_ldu64: configure_opcode_gadget!(),
            op_ldu128: configure_opcode_gadget!(),
            op_ldu256: configure_opcode_gadget!(),
            op_ld_const: configure_opcode_gadget!(),
            op_castu8: configure_opcode_gadget!(),
            op_castu16: configure_opcode_gadget!(),
            op_castu32: configure_opcode_gadget!(),
            op_castu64: configure_opcode_gadget!(),
            op_castu128: configure_opcode_gadget!(),
            op_castu256: configure_opcode_gadget!(),
            op_pop: configure_opcode_gadget!(),
            op_ret: configure_opcode_gadget!(),
            op_add: configure_opcode_gadget!(),
            op_mul: configure_opcode_gadget!(),
            op_copy_loc: configure_opcode_gadget!(),
            op_sub: configure_opcode_gadget!(),
            op_div: configure_opcode_gadget!(),
            op_mod: configure_opcode_gadget!(),
            op_ld_true: configure_opcode_gadget!(),
            op_ld_false: configure_opcode_gadget!(),
            op_eq: configure_opcode_gadget!(),
            op_neq: configure_opcode_gadget!(),
            op_shl: configure_opcode_gadget!(),
            op_shr: configure_opcode_gadget!(),
            op_bit_and: configure_opcode_gadget!(),
            op_bit_or: configure_opcode_gadget!(),
            op_xor: configure_opcode_gadget!(),
            op_and: configure_opcode_gadget!(),
            op_or: configure_opcode_gadget!(),
            op_not: configure_opcode_gadget!(),
            op_move_loc: configure_opcode_gadget!(),
            op_st_loc: configure_opcode_gadget!(),
            op_branch: configure_opcode_gadget!(),
            op_br_true: configure_opcode_gadget!(),
            op_br_false: configure_opcode_gadget!(),
            op_call: configure_opcode_gadget!(),
            op_abort: configure_opcode_gadget!(),
            op_le: configure_opcode_gadget!(),
            op_lt: configure_opcode_gadget!(),
            op_ge: configure_opcode_gadget!(),
            op_gt: configure_opcode_gadget!(),
            op_pack: configure_opcode_gadget!(),
            op_unpack: configure_opcode_gadget!(),
            op_mut_borrow_loc: configure_opcode_gadget!(),
            op_imm_borrow_loc: configure_opcode_gadget!(),
            op_read_ref: configure_opcode_gadget!(),
            op_write_ref: configure_opcode_gadget!(),
            op_freeze_ref: configure_opcode_gadget!(),
            op_imm_borrow_field: configure_opcode_gadget!(),
            op_mut_borrow_field: configure_opcode_gadget!(),
            op_move_from: configure_opcode_gadget!(),
            op_move_to: configure_opcode_gadget!(),
            op_exists: configure_opcode_gadget!(),
            op_imm_borrow_global: configure_opcode_gadget!(),
            op_mut_borrow_global: configure_opcode_gadget!(),
            op_vec_imm_borrow: configure_opcode_gadget!(),
            op_vec_mut_borrow: configure_opcode_gadget!(),
            op_vec_len: configure_opcode_gadget!(),
            op_vec_pack: configure_opcode_gadget!(),
            op_vec_pop_back: configure_opcode_gadget!(),
            op_vec_push_back: configure_opcode_gadget!(),
            op_vec_swap: configure_opcode_gadget!(),
            op_vec_unpack: configure_opcode_gadget!(),
            op_call_generic: configure_opcode_gadget!(),
            op_imm_borrow_global_generic: configure_opcode_gadget!(),
            op_mut_borrow_global_generic: configure_opcode_gadget!(),
            op_move_to_generic: configure_opcode_gadget!(),
            op_move_from_generic: configure_opcode_gadget!(),
            op_exists_generic: configure_opcode_gadget!(),
            op_pack_generic: configure_opcode_gadget!(),
            op_unpack_generic: configure_opcode_gadget!(),
            op_imm_borrow_field_generic: configure_opcode_gadget!(),
            op_mut_borrow_field_generic: configure_opcode_gadget!(),
            op_stop: configure_opcode_gadget!(),
            op_nop: configure_opcode_gadget!(),

            step: step_curr,
            height_map,
            lookup_table: LookupTableConfig::configure(meta, lookups, s_usable, s_step),
        }
    }

    fn configure_opcode_gadget<G: InstructionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        lookups: &mut Vec<(&'static str, ConditionalLookup<F>)>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        s_usable: Selector,
        s_step: Column<Advice>,
        step_curr: &StepConfig<F>,
        height_map: &mut HashMap<Opcode, usize>,
    ) -> G {
        // Configure the gadget with the max height first so we can find out the actual
        // height
        let height = {
            let dummy_step_next = StepChip::configure(meta, advices, STEP_HEIGHT, true);
            let mut dummy_cb =
                ConstraintBuilder::new(step_curr.clone(), dummy_step_next, G::OPCODE);
            let _gadget = G::construct(&mut dummy_cb);
            let (_, _, height) = dummy_cb.build();
            height
        };

        // Now actually configure the gadget with the correct minimal height
        let step_next = StepChip::configure(meta, advices, height, true);
        let mut cb = ConstraintBuilder::new(step_curr.clone(), step_next, G::OPCODE);
        let gadget = G::construct(&mut cb);
        gadget.configure(&step_curr.cells, &mut cb);

        Self::configure_opcode_gadget_impl(
            meta,
            s_usable,
            s_step,
            step_curr,
            height_map,
            G::NAME,
            G::OPCODE,
            height,
            cb,
            lookups,
        );

        gadget
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_opcode_gadget_impl(
        meta: &mut ConstraintSystem<F>,
        s_usable: Selector,
        s_step: Column<Advice>,
        _step_curr: &StepConfig<F>,
        height_map: &mut HashMap<Opcode, usize>,
        name: &'static str,
        opcode: Opcode,
        height: usize,
        cb: ConstraintBuilder<F>,
        lookups: &mut Vec<(&'static str, ConditionalLookup<F>)>,
    ) {
        // insert height into hash table
        debug_assert!(
            !height_map.contains_key(&opcode),
            "execution state already configured"
        );
        height_map.insert(opcode, height);

        // install constraint entries for gadget
        let (constraints, mut op_lookups, _) = cb.build();
        if !constraints.is_empty() {
            meta.create_gate(name, |meta| {
                let s_usable = meta.query_selector(s_usable);
                let s_step = meta.query_advice(s_step, Rotation::cur());
                Constraints::with_selector(
                    s_usable * s_step,
                    constraints.into_iter().map(|(name, c)| (name, c.expr())),
                )
            });
        }
        lookups.append(&mut op_lookups);
    }

    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<
        (
            Option<AssignedCell<F, F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
        ),
        Error,
    > {
        let step_chip = StepChip::<F>::construct(self.config.step.clone(), ());

        let last_step_gc_cell = layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                // Annotate columns within it's single region.
                self.annotate_circuit(&mut region);

                let mut exec_steps = self.witness.exec_steps.clone();
                let last_step = exec_steps.pop().expect("exec steps non-empty");
                debug_assert_eq!(last_step.opcode, Opcode::Stop);
                debug_assert_eq!(self.step_height_get(&last_step.opcode), 1);

                let mut offset = 0;

                // enable step_first
                self.config.s_step_first.enable(&mut region, offset)?;
                // part1: assign normal steps before Opcode::Stop.
                for step in &exec_steps {
                    let step_height = self.step_height_get(&step.opcode);
                    self.assign_s_step(&mut region, offset, step_height)?;

                    // assign step state
                    step_chip.assign(&mut region, offset, step, &self.witness.rw_operations)?;

                    // assign gadget
                    self.assign_gadegt(
                        &mut region,
                        offset,
                        step,
                        &self.witness.rw_operations,
                        &self.config.step.cells,
                    )?;

                    offset += step_height;
                }
                // part2: if padding is needed, assign Opcode::Nop in the padding range.
                // This happened when an execution path is not fixed, for example, if there
                // is loop in the code.
                if let Some(max_row) = self.witness.circuit_config.max_step_row {
                    if offset >= max_row {
                        error!(
                            "execution circuit offset larger than max rows: {} > {}",
                            offset, max_row
                        );
                        return Err(Error::Synthesis);
                    }
                    let height = self.step_height_get(&Opcode::Nop);
                    debug_assert_eq!(height, 1);
                    let last_row = max_row - 1;
                    trace!("assign Nop in range [{}, {})", offset, last_row);
                    let nop_step = {
                        let mut nop = last_step.clone();
                        nop.opcode = Opcode::Nop;
                        nop
                    };
                    for offset in offset..last_row {
                        // enable s_step
                        self.assign_s_step(&mut region, offset, 1)?;

                        // assign step state
                        step_chip.assign(
                            &mut region,
                            offset,
                            &nop_step,
                            &self.witness.rw_operations,
                        )?;

                        // assign gadget
                        self.assign_gadegt(
                            &mut region,
                            offset,
                            &nop_step,
                            &self.witness.rw_operations,
                            &self.config.step.cells,
                        )?;
                    }

                    offset = last_row;
                }

                // part3: assign last step of Opcode::Stop
                let last_step_gc_cell = {
                    self.assign_s_step(&mut region, offset, 1)?;
                    // assign step state
                    let gc_cell = step_chip.assign(
                        &mut region,
                        offset,
                        &last_step,
                        &self.witness.rw_operations,
                    )?;

                    // assign gadget
                    self.assign_gadegt(
                        &mut region,
                        offset,
                        &last_step,
                        &self.witness.rw_operations,
                        &self.config.step.cells,
                    )?;
                    gc_cell
                };
                // part4:
                // These are still referenced (but not used) in next rows
                region.assign_advice(
                    || "step height",
                    self.config.num_rows_until_next_step,
                    offset + 1,
                    || Value::known(F::zero()),
                )?;
                region.assign_advice(
                    || "step height inv",
                    self.config.num_rows_inv,
                    offset + 1,
                    || Value::known(F::zero()),
                )?;

                Ok(last_step_gc_cell)
            },
        )?;

        let (stack_operations, locals_operations, global_operations) =
            LookupTableConfig::assign(layouter, self)?;

        Ok((
            last_step_gc_cell,
            stack_operations,
            locals_operations,
            global_operations,
        ))
    }

    fn step_height_get(&self, opcode: &Opcode) -> usize {
        self.config
            .height_map
            .get(opcode)
            .copied()
            .unwrap_or_else(|| panic!("Execution state unknown: {:?}", self))
    }
    fn assign_s_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        height: usize,
    ) -> Result<(), Error> {
        for idx in 0..height {
            self.config.s_usable.enable(region, offset + idx)?;
            region.assign_advice(
                || "step selector",
                self.config.s_step,
                offset + idx,
                || Value::known(if idx == 0 { F::one() } else { F::zero() }),
            )?;
            let num_rows_until_next_step = if idx == 0 {
                F::zero()
            } else {
                F::from((height - idx) as u64)
            };
            region.assign_advice(
                || "step height",
                self.config.num_rows_until_next_step,
                offset + idx,
                || Value::known(num_rows_until_next_step),
            )?;
            region.assign_advice(
                || "step height inv",
                self.config.num_rows_inv,
                offset + idx,
                || Value::known(num_rows_until_next_step.invert().unwrap_or(F::zero())),
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_gadegt(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        macro_rules! assign_opcode_gadget {
            ($gadget:expr) => {
                $gadget.assign(region, offset, step, rw_operations, cells)?
            };
        }

        match step.opcode {
            Opcode::LdU8 => assign_opcode_gadget!(self.config.op_ldu8),
            Opcode::LdU16 => assign_opcode_gadget!(self.config.op_ldu16),
            Opcode::LdU32 => assign_opcode_gadget!(self.config.op_ldu32),
            Opcode::LdU64 => assign_opcode_gadget!(self.config.op_ldu64),
            Opcode::LdU128 => assign_opcode_gadget!(self.config.op_ldu128),
            Opcode::LdU256 => assign_opcode_gadget!(self.config.op_ldu256),
            Opcode::LdConst => assign_opcode_gadget!(self.config.op_ld_const),
            Opcode::CastU8 => assign_opcode_gadget!(self.config.op_castu8),
            Opcode::CastU16 => assign_opcode_gadget!(self.config.op_castu16),
            Opcode::CastU32 => assign_opcode_gadget!(self.config.op_castu32),
            Opcode::CastU64 => assign_opcode_gadget!(self.config.op_castu64),
            Opcode::CastU128 => assign_opcode_gadget!(self.config.op_castu128),
            Opcode::CastU256 => assign_opcode_gadget!(self.config.op_castu256),
            Opcode::Pop => assign_opcode_gadget!(self.config.op_pop),
            Opcode::Ret => assign_opcode_gadget!(self.config.op_ret),
            Opcode::Xor => assign_opcode_gadget!(self.config.op_xor),
            Opcode::Add => assign_opcode_gadget!(self.config.op_add),
            Opcode::Mul => assign_opcode_gadget!(self.config.op_mul),
            Opcode::CopyLoc => assign_opcode_gadget!(self.config.op_copy_loc),
            Opcode::Sub => assign_opcode_gadget!(self.config.op_sub),
            Opcode::Div => assign_opcode_gadget!(self.config.op_div),
            Opcode::Mod => assign_opcode_gadget!(self.config.op_mod),
            Opcode::LdFalse => assign_opcode_gadget!(self.config.op_ld_false),
            Opcode::LdTrue => assign_opcode_gadget!(self.config.op_ld_true),
            Opcode::Eq => assign_opcode_gadget!(self.config.op_eq),
            Opcode::Neq => assign_opcode_gadget!(self.config.op_neq),
            Opcode::Shl => assign_opcode_gadget!(self.config.op_shl),
            Opcode::Shr => assign_opcode_gadget!(self.config.op_shr),
            Opcode::BitAnd => assign_opcode_gadget!(self.config.op_bit_and),
            Opcode::BitOr => assign_opcode_gadget!(self.config.op_bit_or),
            Opcode::And => assign_opcode_gadget!(self.config.op_and),
            Opcode::Or => assign_opcode_gadget!(self.config.op_or),
            Opcode::Not => assign_opcode_gadget!(self.config.op_not),
            Opcode::MoveLoc => assign_opcode_gadget!(self.config.op_move_loc),
            Opcode::StLoc => assign_opcode_gadget!(self.config.op_st_loc),
            Opcode::Branch => assign_opcode_gadget!(self.config.op_branch),
            Opcode::BrTrue => assign_opcode_gadget!(self.config.op_br_true),
            Opcode::BrFalse => assign_opcode_gadget!(self.config.op_br_false),
            Opcode::Call => assign_opcode_gadget!(self.config.op_call),
            Opcode::Abort => assign_opcode_gadget!(self.config.op_abort),
            Opcode::Le => assign_opcode_gadget!(self.config.op_le),
            Opcode::Lt => assign_opcode_gadget!(self.config.op_lt),
            Opcode::Ge => assign_opcode_gadget!(self.config.op_ge),
            Opcode::Gt => assign_opcode_gadget!(self.config.op_gt),
            Opcode::Pack => assign_opcode_gadget!(self.config.op_pack),
            Opcode::Unpack => assign_opcode_gadget!(self.config.op_unpack),
            Opcode::MutBorrowLoc => assign_opcode_gadget!(self.config.op_mut_borrow_loc),
            Opcode::ImmBorrowLoc => assign_opcode_gadget!(self.config.op_imm_borrow_loc),
            Opcode::ReadRef => assign_opcode_gadget!(self.config.op_read_ref),
            Opcode::WriteRef => assign_opcode_gadget!(self.config.op_write_ref),
            Opcode::FreezeRef => assign_opcode_gadget!(self.config.op_freeze_ref),
            Opcode::ImmBorrowField => assign_opcode_gadget!(self.config.op_imm_borrow_field),
            Opcode::MutBorrowField => assign_opcode_gadget!(self.config.op_mut_borrow_field),
            Opcode::MoveFrom => assign_opcode_gadget!(self.config.op_move_from),
            Opcode::MoveTo => assign_opcode_gadget!(self.config.op_move_to),
            Opcode::Exists => assign_opcode_gadget!(self.config.op_exists),
            Opcode::ImmBorrowGlobal => assign_opcode_gadget!(self.config.op_imm_borrow_global),
            Opcode::MutBorrowGlobal => assign_opcode_gadget!(self.config.op_mut_borrow_global),
            Opcode::VecImmBorrow => assign_opcode_gadget!(self.config.op_vec_imm_borrow),
            Opcode::VecMutBorrow => assign_opcode_gadget!(self.config.op_vec_mut_borrow),
            Opcode::VecLen => assign_opcode_gadget!(self.config.op_vec_len),
            Opcode::VecPack => assign_opcode_gadget!(self.config.op_vec_pack),
            Opcode::VecPopBack => assign_opcode_gadget!(self.config.op_vec_pop_back),
            Opcode::VecPushBack => assign_opcode_gadget!(self.config.op_vec_push_back),
            Opcode::VecSwap => assign_opcode_gadget!(self.config.op_vec_swap),
            Opcode::VecUnpack => assign_opcode_gadget!(self.config.op_vec_unpack),
            Opcode::CallGeneric => assign_opcode_gadget!(self.config.op_call_generic),
            Opcode::ImmBorrowGlobalGeneric => {
                assign_opcode_gadget!(self.config.op_imm_borrow_global_generic)
            }

            Opcode::MutBorrowGlobalGeneric => {
                assign_opcode_gadget!(self.config.op_mut_borrow_global_generic)
            }
            Opcode::MoveFromGeneric => assign_opcode_gadget!(self.config.op_move_from_generic),
            Opcode::MoveToGeneric => assign_opcode_gadget!(self.config.op_move_to_generic),
            Opcode::PackGeneric => assign_opcode_gadget!(self.config.op_pack_generic),
            Opcode::UnpackGeneric => assign_opcode_gadget!(self.config.op_unpack_generic),
            Opcode::ImmBorrowFieldGeneric => {
                assign_opcode_gadget!(self.config.op_imm_borrow_field_generic)
            }
            Opcode::MutBorrowFieldGeneric => {
                assign_opcode_gadget!(self.config.op_mut_borrow_field_generic)
            }
            Opcode::ExistsGeneric => assign_opcode_gadget!(self.config.op_exists_generic),
            Opcode::Stop => assign_opcode_gadget!(self.config.op_stop),
            Opcode::Nop => assign_opcode_gadget!(self.config.op_nop),
        }

        Ok(())
    }
    fn annotate_circuit(&self, region: &mut Region<F>) {
        region.name_column(|| "Exec_s_step", self.config.s_step);
        region.name_column(
            || "Exec_num_rows_until_next_step",
            self.config.num_rows_until_next_step,
        );
        region.name_column(|| "Exec_num_rows_inv", self.config.num_rows_inv);
    }
}
