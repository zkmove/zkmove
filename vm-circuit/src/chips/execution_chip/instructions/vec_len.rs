// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::{
    LookupBytecode, RefVal, ValueHeaderGadget, Word,
};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::{rw_table::RWLookup, LookupsWithCondition};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::Error;
use logger::prelude::*;
use movelang::value::value_header::ValueHeader;
use movelang::value::DEPTH_OF_ADDRESS_PATH;

#[derive(Clone, Debug)]
pub struct VecLen<F: FieldExt> {
    ref_val: Vec<Cell<F>>,
    ref_val_mask: Vec<Cell<F>>,

    vec_header_value: Cell<F>,
    vec_flattened_len: Cell<F>,
    vec_len: Cell<F>,
    vec_frame_index_or_global_address: Cell<F>,
    vec_locals_index_or_global_sd_idx: Cell<F>,
    vec_header_addr_ext_0: Cell<F>,
    vec_header_addr_ext_1: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for VecLen<F> {
    const NAME: &'static str = "VEC_LEN";

    const OPCODE: Opcode = Opcode::VecLen;

    fn configure(
        &self,
        cells: &StepChipCells<F>,
        cb: &mut ConstraintBuilder<F>,
        lookups: &mut LookupsWithCondition<F>,
    ) {
        // for instruction VecLen, there are 3 steps here:
        // 1. read reference from stack. [gc, DEPTH_OF_ADDRESS_PATH]
        // 2. read vec header from locals or global. [gc+DEPTH_OF_ADDRESS_PATH, 1]
        // 3. write length into stack. [gc+DEPTH_OF_ADDRESS_PATH+1, 1]
        let cond = cells.opcode_selector([Self::OPCODE]);

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let depth_of_addr_path_expr = (DEPTH_OF_ADDRESS_PATH as u64).expr();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + depth_of_addr_path_expr.clone()
            + 2.expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond.clone() * func_index),
        ]);

        for (i, item) in self.ref_val.iter().enumerate().take(DEPTH_OF_ADDRESS_PATH) {
            lookups.rw_lookups.push((
                "vec_len(stack pop ref_val)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    0.expr(),
                    item.expression.clone(),
                ),
                cond.clone(),
            ));
        }

        let is_global = cells.auxiliary_1.expression.clone();
        // locals read or global read
        let read_local = RWLookup::locals_read(
            cells.gc.expression.clone() + depth_of_addr_path_expr.clone(),
            self.vec_frame_index_or_global_address.expression.clone(),
            self.vec_locals_index_or_global_sd_idx.expression.clone(),
            self.vec_header_addr_ext_0.expression.clone(),
            self.vec_header_addr_ext_1.expression.clone(),
            self.vec_header_value.expression.clone(),
        );
        lookups.rw_lookups.push((
            "vec_len(read vec header)",
            read_local,
            cond.clone() * (1.expr() - is_global.clone()), // locals read
        ));
        let read_global = RWLookup::global_read(
            cells.gc.expression.clone() + depth_of_addr_path_expr.clone(),
            self.vec_frame_index_or_global_address.expression.clone(),
            self.vec_header_value.expression.clone(),
            self.vec_locals_index_or_global_sd_idx.expression.clone(),
            self.vec_header_addr_ext_0.expression.clone(),
            self.vec_header_addr_ext_1.expression.clone(),
        );
        lookups.rw_lookups.push((
            "vec_len(read vec header)",
            read_global,
            cond.clone() * is_global.clone(), // global read
        ));

        // stack write
        let write = RWLookup::stack_push(
            cells.gc.expression.clone() + depth_of_addr_path_expr + 1.expr(),
            cells.stack_size.expression.clone() - 1.expr(),
            0.expr(),
            0.expr(),
            self.vec_len.expression.clone(),
        );
        lookups
            .rw_lookups
            .push(("vec_len(push len to stack)", write, cond.clone()));

        // cells.ref_val[0] equel to frame_index(Locals) or account_address(Global)
        let mut constraint = cond.clone()
            * (self.ref_val[0].expression.clone()
                - self.vec_frame_index_or_global_address.expression.clone());
        cb.add_constraint("read_ref_eq_0", constraint);
        // cells.ref_val[1] equel to local_index(Locals) or sd_index(Global)
        constraint = cond.clone()
            * (1.expr() - is_global)
            * (self.ref_val[1].expression.clone()
                - self.vec_locals_index_or_global_sd_idx.expression.clone());
        cb.add_constraint("read_ref_eq_1", constraint);
        // cells.ref_val[2] equal to vec_header_addr_ext_0
        constraint = cond.clone()
            * (self.ref_val[2].expression.clone() - self.vec_header_addr_ext_0.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);

        // check vec header
        ValueHeaderGadget::construct(
            self.vec_header_value.expression.clone(),
            self.vec_flattened_len.expression.clone(),
            self.vec_len.expression.clone(),
        )
        .constrain(cb, cond.clone(), "check_vec_header");

        LookupBytecode::lookup_bytecode(
            cells,
            Opcode::VecLen,
            cells.auxiliary_2.expression.clone(),
            &mut lookups.bytecode_lookups,
            cond,
        );
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let _si = Word::assign_step_value(region, offset, &step.auxiliary_2, &cells.auxiliary_2)?;
        let is_global =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?;

        let ref_val = RefVal {
            ref_val: self.ref_val.clone(),
            ref_val_mask: self.ref_val_mask.clone(),
        };
        Word::assign_ref_val(
            region,
            offset,
            step,
            rw_operations,
            &ref_val,
            step.gc,
            DEPTH_OF_ADDRESS_PATH,
        )?;

        let op = rw_operations
            .0
            .get(step.gc + DEPTH_OF_ADDRESS_PATH)
            .ok_or(Error::Synthesis)?;

        // assign vec_header_value, vec_flattened_len
        let header_value = op.value().value().ok_or_else(|| {
            error!("header value is None");
            Error::Synthesis
        })?;
        let vec_flattened_len = ValueHeader::from(header_value).flattened_len();

        self.vec_header_value
            .assign(region, offset, op.value().value())?;
        self.vec_flattened_len
            .assign(region, offset, Some(F::from(vec_flattened_len as u64)))?;

        self.vec_header_addr_ext_0.assign(
            region,
            offset,
            Some(F::from_u128(op.address_ext_0())),
        )?;
        self.vec_header_addr_ext_1.assign(
            region,
            offset,
            Some(F::from(op.address_ext_1() as u64)),
        )?;
        if is_global == F::zero() {
            self.vec_frame_index_or_global_address.assign(
                region,
                offset,
                Some(F::from(op.frame_index() as u64)),
            )?;
            self.vec_locals_index_or_global_sd_idx.assign(
                region,
                offset,
                Some(F::from(op.address() as u64)),
            )?;
        } else {
            self.vec_frame_index_or_global_address.assign(
                region,
                offset,
                Some(op.account_address().value()),
            )?;
            self.vec_locals_index_or_global_sd_idx.assign(
                region,
                offset,
                Some(F::from(op.sd_index() as u64)),
            )?;
        }

        // assign vec_len
        let op = rw_operations
            .0
            .get(step.gc + DEPTH_OF_ADDRESS_PATH + 1)
            .ok_or(Error::Synthesis)?;
        self.vec_len.assign(region, offset, op.value().value())?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let ref_val = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);
        let ref_val_mask = cb.alloc_n_cells(DEPTH_OF_ADDRESS_PATH);

        let vec_header_value = cb.alloc_cell();
        let vec_flattened_len = cb.alloc_cell();
        let vec_len = cb.alloc_cell();
        let vec_frame_index_or_global_address = cb.alloc_cell();
        let vec_locals_index_or_global_sd_idx = cb.alloc_cell();
        let vec_header_addr_ext_0 = cb.alloc_cell();
        let vec_header_addr_ext_1 = cb.alloc_cell();

        Self {
            ref_val,
            ref_val_mask,

            vec_header_value,
            vec_flattened_len,
            vec_len,
            vec_frame_index_or_global_address,
            vec_locals_index_or_global_sd_idx,
            vec_header_addr_ext_0,
            vec_header_addr_ext_1,
        }
    }
}
