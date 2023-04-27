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
use crate::chips::execution_chip::instructions::call_generic::CallGeneric;
use crate::chips::execution_chip::instructions::castu128::CastU128;
use crate::chips::execution_chip::instructions::castu64::CastU64;
use crate::chips::execution_chip::instructions::castu8::CastU8;
use crate::chips::execution_chip::instructions::copy_loc::CopyLoc;
use crate::chips::execution_chip::instructions::div::Div;
use crate::chips::execution_chip::instructions::eq::Eq;
use crate::chips::execution_chip::instructions::exists::Exists;
use crate::chips::execution_chip::instructions::freeze_ref::FreezeRef;
use crate::chips::execution_chip::instructions::ge::Ge;
use crate::chips::execution_chip::instructions::gt::Gt;
use crate::chips::execution_chip::instructions::ld_false::LdFalse;
use crate::chips::execution_chip::instructions::ld_true::LdTrue;
use crate::chips::execution_chip::instructions::ldu128::LdU128;
use crate::chips::execution_chip::instructions::ldu64::LdU64;
use crate::chips::execution_chip::instructions::ldu8::LdU8;
use crate::chips::execution_chip::instructions::le::Le;
use crate::chips::execution_chip::instructions::lt::Lt;
use crate::chips::execution_chip::instructions::move_from::MoveFrom;
use crate::chips::execution_chip::instructions::move_loc::MoveLoc;
use crate::chips::execution_chip::instructions::move_to::MoveTo;
use crate::chips::execution_chip::instructions::mul::Mul;
use crate::chips::execution_chip::instructions::neq::Neq;
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
use crate::chips::execution_chip::instructions::write_ref::WriteRef;
use crate::chips::execution_chip::instructions::xor::Xor;

use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{LookupTableConfig, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::chips::execution_chip::step_chip::{StepChip, StepChipCells, StepConfig};
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::rw_operations::RWOperations;
use crate::witness::Witness;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
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
    pub s_step: Selector,
    step: StepConfig<F>,
    pub(crate) height_map: HashMap<Opcode, usize>,

    // opcode gadget
    op_ldu8: Box<LdU8<F>>,
    op_ldu64: Box<LdU64<F>>,
    op_ldu128: Box<LdU128<F>>,
    op_castu8: Box<CastU8<F>>,
    op_castu64: Box<CastU64<F>>,
    op_castu128: Box<CastU128<F>>,
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
    op_eq: Box<Eq<F>>,
    op_neq: Box<Neq<F>>,
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
    op_call: Box<Call<F>>,
    op_abort: Box<Abort<F>>,
    op_le: Box<Le<F>>,
    op_lt: Box<Lt<F>>,
    op_ge: Box<Ge<F>>,
    op_gt: Box<Gt<F>>,
    op_pack: Box<Pack<F>>,
    op_unpack: Box<Unpack<F>>,
    op_mut_borrow_loc: Box<BorrowLoc<true, F>>,
    op_imm_borrow_loc: Box<BorrowLoc<false, F>>,
    op_read_ref: Box<ReadRef<F>>,
    op_write_ref: Box<WriteRef<F>>,
    op_freeze_ref: Box<FreezeRef<F>>,
    op_imm_borrow_field: Box<BorrowField<false, F>>,
    op_mut_borrow_field: Box<BorrowField<true, F>>,
    op_move_from: Box<MoveFrom<F>>,
    op_move_to: Box<MoveTo<F>>,
    op_exists: Box<Exists<F>>,
    op_imm_borrow_global: Box<BorrowGlobal<false, F>>,
    op_mut_borrow_global: Box<BorrowGlobal<true, F>>,
    op_call_generic: Box<CallGeneric<F>>,
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

        let s_step = meta.complex_selector();

        let step_curr = StepChip::configure(meta, advices, 0, false);

        let mut height_map = HashMap::new();

        let mut lookups = LookupsWithCondition::new();

        macro_rules! configure_opcode_gadget {
            () => {
                Box::new(Self::configure_opcode_gadget(
                    meta,
                    &mut lookups,
                    advices,
                    s_step,
                    &step_curr,
                    &mut height_map,
                ))
            };
        }

        ExecutionChipConfig {
            s_step,
            op_ldu8: configure_opcode_gadget!(),
            op_ldu64: configure_opcode_gadget!(),
            op_ldu128: configure_opcode_gadget!(),
            op_castu8: configure_opcode_gadget!(),
            op_castu64: configure_opcode_gadget!(),
            op_castu128: configure_opcode_gadget!(),
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
            op_call_generic: configure_opcode_gadget!(),
            op_stop: configure_opcode_gadget!(),
            op_nop: configure_opcode_gadget!(),

            step: step_curr,
            height_map,

            lookup_table: LookupTableConfig::configure(meta, &lookups, s_step),
        }
    }

    fn configure_opcode_gadget<G: InstructionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        lookups: &mut LookupsWithCondition<F>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        s_step: Selector,
        step_curr: &StepConfig<F>,
        height_map: &mut HashMap<Opcode, usize>,
    ) -> G {
        // Configure the gadget with the max height first so we can find out the actual
        // height
        let (gadget, height) = {
            let dummy_step_next = StepChip::configure(meta, advices, STEP_HEIGHT, true);
            let mut dummy_cb =
                ConstraintBuilder::new(step_curr.clone(), dummy_step_next, G::OPCODE);
            let gadget = G::construct(&mut dummy_cb);
            let (_, height) = dummy_cb.build();
            (gadget, height)
        };

        // Now actually configure the gadget with the correct minimal height
        let step_next = StepChip::configure(meta, advices, height, true);
        let mut cb = ConstraintBuilder::new(step_curr.clone(), step_next, G::OPCODE);

        gadget.configure(&step_curr.cells, &mut cb, lookups);

        Self::configure_opcode_gadget_impl(
            meta,
            s_step,
            step_curr,
            height_map,
            G::NAME,
            G::OPCODE,
            height,
            cb,
        );

        gadget
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_opcode_gadget_impl(
        meta: &mut ConstraintSystem<F>,
        s_step: Selector,
        step_curr: &StepConfig<F>,
        height_map: &mut HashMap<Opcode, usize>,
        name: &'static str,
        opcode: Opcode,
        height: usize,
        cb: ConstraintBuilder<F>,
    ) {
        // config each execution path of the step
        let mut constraints = Vec::new();
        StepChip::constrain_step_conditions(&step_curr.cells, &mut constraints);
        // for (i, constraint) in constraints.iter().enumerate() {
        //     debug!("constraint {}, {:?}", i, constraint);
        // }

        meta.create_gate("constrain step conditions", |meta| {
            let s_step = meta.query_selector(s_step);
            constraints
                .into_iter()
                .map(move |(name, constraint)| (name, s_step.clone() * constraint))
        });

        // insert height into hash table
        debug_assert!(
            !height_map.contains_key(&opcode),
            "execution state already configured"
        );
        height_map.insert(opcode, height);

        // install constraint entries for gadget
        let (constraints, _) = cb.build();
        // for (i, constraint) in constraints.iter().enumerate() {
        //     debug!("constraint {}, {:?}", i, constraint);
        // }
        if !constraints.is_empty() {
            meta.create_gate(name, |meta| {
                let s_step = meta.query_selector(s_step);
                constraints
                    .into_iter()
                    .map(move |(name, constraint)| (name, s_step.clone() * constraint))
            });
        }
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
        let exec_steps = self.witness.process_exec_steps()?;
        let mut gc_cell = None;
        layouter.assign_region(
            || "execution steps",
            |mut region: Region<'_, F>| {
                let mut offset = 0;
                for step in &exec_steps {
                    // enable s_step
                    self.config.s_step.enable(&mut region, offset)?;

                    // assign step state
                    gc_cell =
                        step_chip.assign(&mut region, offset, step, &self.witness.rw_operations)?;

                    // assign gadget
                    self.assign_gadegt(
                        &mut region,
                        offset,
                        step,
                        &self.witness.rw_operations,
                        &self.config.step.cells,
                    )?;

                    let step_height = self.step_height_get(&step.opcode);
                    offset += step_height;
                }
                Ok(())
            },
        )?;
        let last_step_gc_cell = gc_cell;

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
            Opcode::LdU64 => assign_opcode_gadget!(self.config.op_ldu64),
            Opcode::LdU128 => assign_opcode_gadget!(self.config.op_ldu128),
            Opcode::CastU8 => assign_opcode_gadget!(self.config.op_castu8),
            Opcode::CastU64 => assign_opcode_gadget!(self.config.op_castu64),
            Opcode::CastU128 => assign_opcode_gadget!(self.config.op_castu128),
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
            Opcode::CallGeneric => assign_opcode_gadget!(self.config.op_call_generic),
            Opcode::Stop => assign_opcode_gadget!(self.config.op_stop),
            Opcode::Nop => assign_opcode_gadget!(self.config.op_nop),
        }

        Ok(())
    }
}
