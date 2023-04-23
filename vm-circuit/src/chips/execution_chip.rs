// Copyright (c) zkMove Authors
use crate::chips::execution_chip::instructions::add::Add;
use crate::chips::execution_chip::instructions::castu8::CastU8;
use crate::chips::execution_chip::instructions::ldu8::LdU8;
use crate::chips::execution_chip::instructions::move_loc::MoveLoc;
use crate::chips::execution_chip::instructions::nop::Nop;
use crate::chips::execution_chip::instructions::pop::Pop;
use crate::chips::execution_chip::instructions::ret::Ret;

use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::LookupsWithCondition;
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::{STEP_CHIP_WIDTH, STEP_HEIGHT};
use crate::chips::execution_chip::step_chip::{StepChip, StepChipCells, StepConfig};
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::witness::execution_steps::ExecutionStep;
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
    // op_ld64: Box<LdU64<F>>,
    // op_ldu128: Box<LdU128<F>>,
    op_castu8: Box<CastU8<F>>,
    // op_castu64: Box<CastU64<F>>,
    // op_castu128: Box<CastU128<F>>,
    op_pop: Box<Pop<F>>,
    op_ret: Box<Ret<F>>,
    op_add: Box<Add<F>>,
    // op_mul: Box<Mul<F>>,
    // op_copy_loc: Box<CopyLoc<F>>,
    // op_sub: Box<Sub<F>>,
    // op_div: Box<Div<F>>,
    // op_mod: Box<Mod<F>>,
    // op_ld_true: Box<LdTrue<F>>,
    // op_ld_false: Box<LdFalse<F>>,
    // op_eq: Box<Eq<F>>,
    // op_neq: Box<Neq<F>>,
    // op_shl: Box<Shl<F>>,
    // op_shr: Box<Shr<F>>,
    // op_bit_and: Box<BitAnd<F>>,
    // op_bit_or: Box<BitOr<F>>,
    // op_xor: Box<Xor<F>>,
    // op_and: Box<And<F>>,
    // op_or: Box<Or<F>>,
    // op_not: Box<Not<F>>,
    op_move_loc: Box<MoveLoc<F>>,
    // op_st_loc: Box<StLoc<F>>,
    // op_branch: Box<Branch<F>>,
    // op_br_true: Box<BrTrue<F>>,
    // op_br_false: Box<BrFalse<F>>,
    // op_call: Box<Call<F>>,
    // op_abort: Box<Abort<F>>,
    // op_le: Box<Le<F>>,
    // op_lt: Box<Lt<F>>,
    // op_ge: Box<Ge<F>>,
    // op_gt: Box<Gt<F>>,
    // op_pack: Box<Pack<F>>,
    // op_unpack: Box<Unpack<F>>,
    // op_mut_borrow_loc: Box<BorrowLoc<true, F>>,
    // op_imm_borrow_loc: Box<BorrowLoc<false, F>>,
    // op_read_ref: Box<ReadRef<F>>,
    // op_write_ref: Box<WriteRef<F>>,
    // op_freeze_ref: Box<FreezeRef<F>>,
    // op_imm_borrow_field: Box<BorrowField<false, F>>,
    // op_mut_borrow_field: Box<BorrowField<true, F>>,
    // op_move_from: Box<MoveFrom<F>>,
    // op_move_to: Box<MoveTo<F>>,
    // op_exists: Box<Exists<F>>,
    // op_imm_borrow_global: Box<BorrowGlobal<false, F>>,
    // op_mut_borrow_global: Box<BorrowGlobal<true, F>>,
    // op_call_generic: Box<CallGeneric<F>>,
    // op_stop: Box<Stop<F>>,
    op_nop: Box<Nop<F>>,
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

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) -> <Self as Chip<F>>::Config {
        let advices = [(); STEP_CHIP_WIDTH].map(|_| meta.advice_column());

        let s_step = meta.complex_selector();

        let step_curr = StepChip::configure(meta, advices, 0, false);

        let mut height_map = HashMap::new();

        macro_rules! configure_gadget {
            () => {
                Box::new(Self::configure_gadget(
                    meta,
                    lookups,
                    advices,
                    s_step,
                    &step_curr,
                    &mut height_map,
                ))
            };
        }

        ExecutionChipConfig {
            s_step,
            height_map: height_map.clone(),
            op_ldu8: configure_gadget!(),
            // op_ld64:    configure_gadget!(),
            // op_ldu128:  configure_gadget!(),
            op_castu8: configure_gadget!(),
            // op_castu64: configure_gadget!(),
            // op_castu128:configure_gadget!(),
            op_pop: configure_gadget!(),
            op_ret: configure_gadget!(),
            op_add: configure_gadget!(),
            // op_mul:     configure_gadget!(),
            // op_copy_loc:configure_gadget!(),
            // op_sub:     configure_gadget!(),
            // op_div:     configure_gadget!(),
            // op_mod:     configure_gadget!(),
            // op_ld_true: configure_gadget!(),
            // op_ld_false:configure_gadget!(),
            // op_eq:      configure_gadget!(),
            // op_neq:     configure_gadget!(),
            // op_shl:     configure_gadget!(),
            // op_shr:     configure_gadget!(),
            // op_bit_and: configure_gadget!(),
            // op_bit_or:  configure_gadget!(),
            // op_xor:     configure_gadget!(),
            // op_and:     configure_gadget!(),
            // op_or:      configure_gadget!(),
            // op_not:     configure_gadget!(),
            op_move_loc: configure_gadget!(),
            // op_st_loc:  configure_gadget!(),
            // op_branch:  configure_gadget!(),
            // op_br_true: configure_gadget!(),
            // op_br_false: configure_gadget!(),
            // op_call:    configure_gadget!(),
            // op_abort:   configure_gadget!(),
            // op_le:      configure_gadget!(),
            // op_lt:      configure_gadget!(),
            // op_ge:      configure_gadget!(),
            // op_gt:      configure_gadget!(),
            // op_pack:    configure_gadget!(),
            // op_unpack:  configure_gadget!(),
            // op_mut_borrow_loc: configure_gadget!(),
            // op_imm_borrow_loc: configure_gadget!(),
            // op_read_ref:       configure_gadget!(),
            // op_write_ref:      configure_gadget!(),
            // op_freeze_ref:     configure_gadget!(),
            // op_imm_borrow_field: configure_gadget!(),
            // op_mut_borrow_field: configure_gadget!(),
            // op_move_from:        configure_gadget!(),
            // op_move_to:          configure_gadget!(),
            // op_exists:           configure_gadget!(),
            // op_imm_borrow_global: configure_gadget!(),
            // op_mut_borrow_global: configure_gadget!(),
            // op_call_generic:      configure_gadget!(),
            // op_stop:              configure_gadget!(),
            op_nop: configure_gadget!(),
            step: step_curr,
        }
    }

    fn configure_gadget<G: InstructionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        lookups: &mut LookupsWithCondition<F>,
        advices: [Column<Advice>; STEP_CHIP_WIDTH],
        s_step: Selector,
        step_curr: &StepConfig<F>,
        height_map: &mut HashMap<Opcode, usize>,
    ) -> G {
        // Configure the gadget with the max height first so we can find out the actual
        // height
        let height = {
            let dummy_step_next = StepChip::configure(meta, advices, STEP_HEIGHT, true);
            let mut cb = ConstraintBuilder::new(step_curr.clone(), dummy_step_next, G::OPCODE);
            G::configure(&step_curr.cells, &mut cb, lookups);
            let (_, height) = cb.build();
            height
        };

        // Now actually configure the gadget with the correct minimal height
        let step_next = &StepChip::configure(meta, advices, height, true);
        let mut cb = ConstraintBuilder::new(step_curr.clone(), step_next.clone(), G::OPCODE);

        let gadget = G::configure(&step_curr.cells, &mut cb, lookups);

        Self::configure_gadget_impl(
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
    fn configure_gadget_impl(
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

        // // Enforce the step height for this opcode
        // let num_rows_until_next_step_next = query_expression(meta, |meta| {
        //     meta.query_advice(num_rows_until_next_step, Rotation::next())
        // });
        // cb.require_equal(
        //     "num_rows_until_next_step_next := height - 1",
        //     num_rows_until_next_step_next,
        //     (height - 1).expr(),
        // );
        // instrument.on_gadget_built(execution_state, &cb);

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

        // // Enforce the logic for this opcode
        // let sel_step: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
        //     &|meta| meta.query_advice(q_step, Rotation::cur());
        // let sel_step_first: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
        //     &|meta| meta.query_selector(q_step_first);
        // let sel_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
        //     &|meta| meta.query_selector(q_step_last);
        // let sel_not_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
        //     meta.query_advice(q_step, Rotation::cur()) * not::expr(meta.query_selector(q_step_last))
        // };

        // for (selector, constraints) in [
        //     (sel_step, constraints.step),
        //     (sel_step_first, constraints.step_first),
        //     (sel_step_last, constraints.step_last),
        //     (sel_not_step_last, constraints.not_step_last),
        // ] {
        //     if !constraints.is_empty() {
        //         meta.create_gate(name, |meta| {
        //             let q_usable = meta.query_selector(q_usable);
        //             let selector = selector(meta);
        //             constraints.into_iter().map(move |(name, constraint)| {
        //                 (name, q_usable.clone() * selector.clone() * constraint)
        //             })
        //         });
        //     }
        // }
    }

    #[allow(clippy::type_complexity)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Option<AssignedCell<F, F>>, Error> {
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

                    let step_height = step.opcode.get_step_height();
                    offset += step_height;
                }
                Ok(())
            },
        )?;
        let last_step_gc_cell = gc_cell;

        Ok(last_step_gc_cell)
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
        macro_rules! assign_exec_step {
            ($gadget:expr) => {
                $gadget.assign(region, offset, step, rw_operations, cells)?
            };
        }

        match step.opcode {
            Opcode::LdU8 => assign_exec_step!(self.config.op_ldu8),
            Opcode::CastU8 => assign_exec_step!(self.config.op_castu8),
            Opcode::Pop => assign_exec_step!(self.config.op_pop),
            Opcode::Ret => assign_exec_step!(self.config.op_ret),
            Opcode::Add => assign_exec_step!(self.config.op_add),
            Opcode::MoveLoc => assign_exec_step!(self.config.op_move_loc),
            Opcode::Nop => assign_exec_step!(self.config.op_nop),
            _ => todo!(),
        }

        Ok(())
    }
}
