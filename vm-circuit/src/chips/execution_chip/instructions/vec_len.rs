// Copyright (c) zkMove Authors

use crate::chips::execution_chip::instructions::common::reference_value_gadget::RefValGadget;
use crate::chips::execution_chip::instructions::common::simple_value_gadget::SimpleValueGadget;
use crate::chips::execution_chip::instructions::common::{LookupBytecode, ValueHeaderGadget, Word};
use crate::chips::execution_chip::instructions::InstructionGadget;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
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
use movelang::value_ext::{ValueHeader, LEN_OF_SIMPLE_VALUE};
use movelang::value_ext::{LEN_OF_REFERENCE_VALUE, LOWER_FIELD_OFFSET};

#[derive(Clone, Debug)]
pub struct VecLen<F: FieldExt> {
    ref_val: RefValGadget<F>,

    vec_header_value: Cell<F>,
    vec_flattened_len: Cell<F>,
    vec_len: SimpleValueGadget<F>,
    vec_frame_index_or_global_address: Cell<F>,
    vec_locals_index_or_global_sd_idx: Cell<F>,
    vec_header_addr_ext: Cell<F>,
}

impl<F: FieldExt> InstructionGadget<F> for VecLen<F> {
    const NAME: &'static str = "VEC_LEN";

    const OPCODE: Opcode = Opcode::VecLen;

    fn configure(&self, cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        // for instruction VecLen, there are 3 steps here:
        // 1. read reference from stack. [gc, LEN_OF_REFERENCE_VALUE]
        // 2. read vec header from locals or global. [gc+LEN_OF_REFERENCE_VALUE, 1]
        // 3. write length into stack. [gc+LEN_OF_REFERENCE_VALUE+1, LEN_OF_SIMPLE_VALUE]

        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();

        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + (LEN_OF_REFERENCE_VALUE as u64).expr()
            + 1.expr()
            + (LEN_OF_SIMPLE_VALUE as u64).expr();
        let module_index =
            cells.module_index.expression.clone() - cb.next.cells.module_index.expression.clone();
        let func_index = cells.function_index.expression.clone()
            - cb.next.cells.function_index.expression.clone();
        cb.add_constraints(vec![
            ("pc", pc_expr),
            ("stack size", stack_size_expr),
            ("frame index", frame_index_expr),
            ("gc", gc_expr),
            ("module index", module_index),
            ("function index", func_index),
        ]);

        self.ref_val.configure(cb);
        self.vec_len.configure(cb);

        for (i, item) in self.ref_val.cells.as_inner().iter().enumerate() {
            cb.add_lookup(
                "vec_len(stack pop ref_val)",
                RWLookup::stack_pop(
                    cells.gc.expression.clone() + (i as u64).expr(),
                    cells.stack_size.expression.clone(),
                    (i as u64).expr(),
                    item.expression.clone(),
                ),
            );
        }

        let is_global = cells.auxiliary_1.expression.clone();
        // locals read or global read
        let read_local = RWLookup::locals_read(
            cells.gc.expression.clone() + (LEN_OF_REFERENCE_VALUE as u64).expr(),
            self.vec_frame_index_or_global_address.expression.clone(),
            self.vec_locals_index_or_global_sd_idx.expression.clone(),
            self.vec_header_addr_ext.expression.clone(),
            self.vec_header_value.expression.clone(),
        );
        cb.condition(1.expr() - is_global.clone(), |cb| {
            // locals read
            cb.add_lookup("vec_len(read vec header)", read_local);
        });

        let read_global = RWLookup::global_read(
            cells.gc.expression.clone() + (LEN_OF_REFERENCE_VALUE as u64).expr(),
            self.vec_frame_index_or_global_address.expression.clone(),
            self.vec_header_value.expression.clone(),
            self.vec_locals_index_or_global_sd_idx.expression.clone(),
            self.vec_header_addr_ext.expression.clone(),
        );
        // global read
        cb.condition(is_global.clone(), |cb| {
            cb.add_lookup("vec_len(read vec header)", read_global);
        });

        // stack write
        // len is stored at lower field
        let write = RWLookup::stack_push(
            cells.gc.expression.clone() + (LEN_OF_REFERENCE_VALUE as u64).expr() + 1.expr(),
            cells.stack_size.expression.clone() - 1.expr(),
            0.expr(),
            ValueHeader::default_for_simple().expr(),
        );
        cb.add_lookup("vec_len(push value header to stack)", write);
        let write = RWLookup::stack_push(
            cells.gc.expression.clone()
                + (LEN_OF_REFERENCE_VALUE as u64).expr()
                + 1.expr()
                + (LOWER_FIELD_OFFSET as u64).expr(),
            cells.stack_size.expression.clone() - 1.expr(),
            2.expr(),
            self.vec_len.cells.value().expression.clone(),
        );
        cb.add_lookup("vec_len(push len to stack)", write);

        // ref_val[0] equals to ref value header
        let mut constraint =
            self.ref_val.cells[0].expression.clone() - ValueHeader::default_for_ref_val().expr();
        cb.add_constraint("read_ref_eq_0", constraint);

        // ref_val[1] equel to frame_index(Locals) or account_address(Global)
        constraint = self.ref_val.cells[1].expression.clone()
            - self.vec_frame_index_or_global_address.expression.clone();
        cb.add_constraint("read_ref_eq_1", constraint);

        // ref_val[2] equel to local_index(Locals) or sd_index(Global)
        constraint = (1.expr() - is_global)
            * (self.ref_val.cells[2].expression.clone()
                - self.vec_locals_index_or_global_sd_idx.expression.clone());
        cb.add_constraint("read_ref_eq_2", constraint);

        // ref_val[3] equal to vec_header_addr_ext
        constraint =
            self.ref_val.cells[3].expression.clone() - self.vec_header_addr_ext.expression.clone();
        cb.add_constraint("read_ref_eq_3", constraint);

        // check vec header
        ValueHeaderGadget::construct(
            self.vec_header_value.expression.clone(),
            self.vec_flattened_len.expression.clone(),
            self.vec_len.cells.value().expression.clone(),
        )
        .constrain(cb, "check_vec_header");

        LookupBytecode::lookup_bytecode(
            cb,
            cells,
            Opcode::VecLen,
            cells.auxiliary_2.expression.clone(),
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

        self.ref_val
            .assign(region, offset, rw_operations, step.gc)?;

        let op = rw_operations
            .0
            .get(step.gc + LEN_OF_REFERENCE_VALUE)
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

        self.vec_header_addr_ext
            .assign(region, offset, Some(F::from(op.address_ext() as u64)))?;
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
        self.vec_len.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_REFERENCE_VALUE + 1,
        )?;

        Ok(())
    }

    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let ref_val = RefValGadget::construct(cb);
        let vec_header_value = cb.alloc_cell();
        let vec_flattened_len = cb.alloc_cell();
        let vec_len = SimpleValueGadget::construct(cb);
        let vec_frame_index_or_global_address = cb.alloc_cell();
        let vec_locals_index_or_global_sd_idx = cb.alloc_cell();
        let vec_header_addr_ext = cb.alloc_cell();

        Self {
            ref_val,
            vec_header_value,
            vec_flattened_len,
            vec_len,
            vec_frame_index_or_global_address,
            vec_locals_index_or_global_sd_idx,
            vec_header_addr_ext,
        }
    }
}
