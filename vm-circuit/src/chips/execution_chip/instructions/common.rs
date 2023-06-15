use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookup, bitwise_lookup_table::BitwiseLookup,
    bytecode_lookup_table::BytecodeLookup, rw_table::RWLookup,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::MAX_ADDRESS_EXT_LENGTH;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, DeltaInvert, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;

use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use itertools::izip;
use logger::prelude::*;
use movelang::value::{
    Value, DEPTH_OF_LOCATION_PATH, NUM_OF_BYTES_U128, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use movelang::word::{ValueHeader, LEN_OF_REFERENCE_VALUE};
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct BinaryOp<F: FieldExt> {
    pub value_a: Cell<F>,
    pub value_b: Cell<F>,
    pub value_c: Cell<F>,
}

impl<F: FieldExt> BinaryOp<F> {
    pub(crate) fn constrain_binary_op(cb: &mut ConstraintBuilder<F>, cells: &StepChipCells<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        // Each stack push/pop have two rw_op, one is for the value header.
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone() + 6.expr();
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
    }

    pub(crate) fn lookup_binary_op(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        binary_op: &BinaryOp<F>,
    ) {
        cb.add_lookup(
            "binary op(stack pop value_b's header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "binary op(stack pop value_b)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                binary_op.value_b.expression.clone(),
            ),
        );
        cb.add_lookup(
            "binary op(stack pop value_a's header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "binary op(stack pop value_a)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 3.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                1.expr(),
                binary_op.value_a.expression.clone(),
            ),
        );
        cb.add_lookup(
            "binary op(stack push value_c's header)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + 4.expr(),
                cells.stack_size.expression.clone() - 2.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "binary op(stack push value_c)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + 5.expr(),
                cells.stack_size.expression.clone() - 2.expr(),
                1.expr(),
                binary_op.value_c.expression.clone(),
            ),
        );
    }

    pub fn assign_binary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        binary_op: &BinaryOp<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        binary_op
            .value_b
            .assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 3).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        binary_op
            .value_a
            .assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 5).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        binary_op
            .value_c
            .assign(region, offset, op.value().value())?;

        Ok(())
    }

    pub fn assign_binary_op_with_auxiliary(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
        binary_op: &BinaryOp<F>,
    ) -> Result<(), Error> {
        Self::assign_binary_op(region, offset, step, rw_operations, binary_op)?;

        let aux_value = step.auxiliary_1.as_ref().ok_or_else(|| {
            error!("auxiliary_1 is None");
            Error::Synthesis
        })?;
        cells
            .auxiliary_1
            .assign(region, offset, aux_value.value())?;

        Ok(())
    }

    pub fn assign_bitwise_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        lookup_bitwise: &LookupBitwise<F>,
    ) -> Result<(), Error> {
        // store operand 1 at bytes_operand_1 cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc + 3)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in lookup_bitwise.bytes_operand_1.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store operand 2 at bytes_operand_2 cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc + 1)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in lookup_bitwise.bytes_operand_2.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store result at bytes cell.
        // every 4 bits within one cell and cost 16 cells.
        let result = rw_operations
            .0
            .get(step.gc + 5)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in lookup_bitwise.bytes.iter().take(16).enumerate() {
            // seperate one byte into 2 fields
            // for only u64 is supported and little-endian mode. so only first 8 bytes.
            if index % 2 == 0 {
                byte.assign(
                    region,
                    offset,
                    Some(F::from((result_bytes[index / 2] & 0xF) as u64)),
                )?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((result_bytes[index / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        Ok(())
    }
}

pub struct UnaryOp<F: FieldExt> {
    pub value_a: Cell<F>,
    pub value_c: Cell<F>,
}

impl<F: FieldExt> UnaryOp<F> {
    pub(crate) fn constrain_unary_op(cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone() + 4.expr();
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
    }

    pub(crate) fn lookup_unary_op(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        unary_op: &UnaryOp<F>,
    ) {
        cb.add_lookup(
            "unary op(stack pop value header)",
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "unary op(stack pop value)",
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                unary_op.value_a.expression.clone(),
            ),
        );
        cb.add_lookup(
            "unary op(stack push value header)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "unary op(stack push value)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + 3.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                1.expr(),
                unary_op.value_c.expression.clone(),
            ),
        );
    }

    pub fn assign_unary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        unary_op: &UnaryOp<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        unary_op
            .value_a
            .assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 3).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        unary_op
            .value_c
            .assign(region, offset, op.value().value())?;

        Ok(())
    }
}

pub struct LoadOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LoadOp<F> {
    pub(crate) fn constrain_ld_op(cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr = cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone() + 2.expr();
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
    }

    pub(crate) fn lookup_ld_op(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        value: &Cell<F>,
    ) {
        cb.add_lookup(
            "ld op(stack push value header)",
            RWLookup::stack_push(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                ValueHeader::default_for_simple().expr(),
            ),
        );
        cb.add_lookup(
            "ld op(stack push value)",
            RWLookup::stack_push(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone(),
                1.expr(),
                value.expression.clone(),
            ),
        );
    }
}

pub struct LookupBytecode<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LookupBytecode<F> {
    pub(crate) fn lookup_bytecode(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,

        opcode: Opcode,
        bytecode_operand: Expression<F>,
    ) {
        cb.add_lookup(
            "bytecode lookups",
            BytecodeLookup {
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                opcode: (opcode.index() as u64).expr(),
                operand: bytecode_operand,
            },
        );
    }
}

pub struct ArithOverflow<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithOverflow<F> {
    pub(crate) fn constrain_range_check(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        bytes: Vec<Cell<F>>,
        out: Expression<F>,
    ) {
        // arithmetic overflow check
        // if bytes_len = NUM_OF_BYTES_U8, then bytes_1 == out
        // else if bytes_len = NUM_OF_BYTES_U64, then bytes_8 == out
        // else if bytes_len = NUM_OF_BYTES_U128, then bytes_16 == out
        let bytes_1 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let bytes_8 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U64);
        let bytes_16 = FieldBytes::from(bytes).expr_with_n(NUM_OF_BYTES_U128);

        let num_of_bytes = cells.auxiliary_1.expression.clone();
        let delta_inverse_1 = cells.auxiliary_2.expression.clone();
        let delta_inverse_8 = cells.auxiliary_3.expression.clone();
        let delta_inverse_16 = cells.auxiliary_4.expression.clone();

        let cond_1 =
            1.expr() - (num_of_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr()) * delta_inverse_1;
        let cond_8 =
            1.expr() - (num_of_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr()) * delta_inverse_8;
        let cond_16 =
            1.expr() - (num_of_bytes - (NUM_OF_BYTES_U128 as u64).expr()) * delta_inverse_16;

        let constraint_1 = cond_1 * (bytes_1 - out.clone());
        cb.add_constraint("range check 1", constraint_1);
        let constraint_8 = cond_8 * (bytes_8 - out.clone());
        cb.add_constraint("range check 8", constraint_8);
        let constraint_16 = cond_16 * (bytes_16 - out);
        cb.add_constraint("range check 16", constraint_16);
    }

    // lookup (module_index, function_index, pc, num_of_bytes) in the arith op table.
    pub(crate) fn lookup_arith_op(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        num_of_bytes: Expression<F>,
    ) {
        cb.add_lookup(
            "arithmetic op lookups",
            ArithOpLookup {
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                num_of_bytes,
            },
        );
    }

    // given a value, assign it's number of bytes (num_of_bytes) into auxiliary_1
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U8 into auxiliary_2
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U64 into auxiliary_3
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U128 into auxiliary_4
    pub fn assign_num_of_bytes(
        region: &mut Region<'_, F>,
        offset: usize,
        cells: &StepChipCells<F>,
        bytes: Vec<Cell<F>>,
        value: Value<F>,
    ) -> Result<(), Error> {
        // assign value into bytes
        let field = value.value().ok_or_else(|| {
            error!("result is None");
            Error::Synthesis
        })?;
        let value_bytes: [u8; 32] = field
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in bytes.iter().enumerate() {
            byte.assign(region, offset, Some(F::from(value_bytes[index] as u64)))?;
        }

        // assign auxiliary cell with number of bytes
        let num_of_bytes = match value {
            Value::U8(_) => NUM_OF_BYTES_U8 as u128,
            Value::U64(_) => NUM_OF_BYTES_U64 as u128,
            Value::U128(_) => NUM_OF_BYTES_U128 as u128,
            _ => unreachable!(),
        };
        cells
            .auxiliary_1
            .assign(region, offset, Some(F::from_u128(num_of_bytes)))?;

        // assign delta_inverse(num_of_bytes, NUM_OF_BYTES_U8/U64/U128)
        let delta_inverse_1 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U8 as u128));
        let delta_inverse_8 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U64 as u128));
        let delta_inverse_16 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U128 as u128));
        cells.auxiliary_2.assign(region, offset, delta_inverse_1)?;
        cells.auxiliary_3.assign(region, offset, delta_inverse_8)?;
        cells.auxiliary_4.assign(region, offset, delta_inverse_16)?;

        Ok(())
    }
}

pub struct LookupBitwise<F: FieldExt> {
    pub bytes: Vec<Cell<F>>,
    pub bytes_operand_1: Vec<Cell<F>>,
    pub bytes_operand_2: Vec<Cell<F>>,
}

impl<F: FieldExt> LookupBitwise<F> {
    pub(crate) fn lookup_bitwise(
        cb: &mut ConstraintBuilder<F>,
        cells: &LookupBitwise<F>,
        opcode: Opcode,
    ) {
        for (operand_1, operand_2, result_value) in
            izip!(&cells.bytes_operand_1, &cells.bytes_operand_2, &cells.bytes)
        {
            cb.add_lookup(
                "bitwise lookups",
                BitwiseLookup {
                    opcode: (opcode.index() as u64).expr(),
                    value_1: operand_1.expression.clone(),
                    value_2: operand_2.expression.clone(),
                    result: result_value.expression.clone(),
                },
            );
        }
    }
}

pub struct Word<F: FieldExt> {
    pub word: Vec<Cell<F>>,
    pub word_mask: Vec<Cell<F>>,
    pub word_addr_ext_0: Vec<Cell<F>>,
}

pub struct RefVal<F: FieldExt> {
    pub ref_val: Vec<Cell<F>>,
    pub ref_val_mask: Vec<Cell<F>>,
}

impl<F: FieldExt> Word<F> {
    pub fn get_word_element_num(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        cells: &StepChipCells<F>,
    ) -> VmResult<usize> {
        let word_element_num = step.auxiliary_3.as_ref().ok_or_else(|| {
            error!("auxiliary_3 is None");
            Error::Synthesis
        })?;

        // assign to cells.auxiliary_3
        cells
            .auxiliary_3
            .assign(region, offset, word_element_num.value())?;

        // return word_element_num
        Ok(word_element_num
            .value()
            .ok_or_else(|| {
                error!("failed to get word_element_num");
                Error::Synthesis
            })?
            .get_lower_128() as usize)
    }

    pub fn assign_step_value(
        region: &mut Region<'_, F>,
        offset: usize,
        step_value: &Option<Value<F>>,
        cell: &Cell<F>,
    ) -> VmResult<F> {
        let value = step_value.as_ref().ok_or_else(|| {
            error!("step value {:?} is None", step_value);
            Error::Synthesis
        })?;
        cell.assign(region, offset, value.value())?;

        Ok(value.value().ok_or_else(|| {
            error!("failed to get step value {:?}", step_value);
            Error::Synthesis
        })?)
    }
    pub fn assign_offset_pow2(
        region: &mut Region<'_, F>,
        offset: usize,
        step_value: &Option<Value<F>>,
        cell: &Cell<F>,
    ) -> VmResult<F> {
        // the address length is parsed by ExecutionStep.
        let len_of_address = step_value
            .as_ref()
            .ok_or_else(|| {
                error!("step value {:?} is None", step_value);
                Error::Synthesis
            })?
            .value()
            .unwrap()
            .get_lower_32();

        // offset within addr_ext is address length sub DEPTH_OF_LOCATION_PATH.
        let addr_ext_offset = len_of_address - (DEPTH_OF_LOCATION_PATH as u32);
        if addr_ext_offset >= (MAX_ADDRESS_EXT_LENGTH as u32) {
            error!("ref value {:?} is out of bound", step_value);
            return Err(RuntimeError::new(StatusCode::OutOfBounds));
        }

        // every layer of addres extend is 16 bits. max 65535 members.
        let pow2_of_val = F::from_u128(2).pow(&[(addr_ext_offset * 16) as u64, 0, 0, 0]);
        cell.assign(region, offset, Some(pow2_of_val))?;

        Ok(pow2_of_val)
    }

    pub fn assign_word(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &Word<F>,
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        for (i, _) in cells.word.iter().enumerate().take(word_element_num) {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
        }

        for (i, _) in cells.word.iter().enumerate().skip(word_element_num) {
            cells.word_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_word_with_capacity(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &Word<F>,
        op_index: usize,
        word_element_num: usize,
        capacity: usize,
    ) -> Result<(), Error> {
        for i in 0..word_element_num {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
        }

        debug_assert!(word_element_num <= capacity);

        for i in word_element_num..capacity {
            cells.word_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    // NOTICE: this function is used for pack/unpack a container type.
    // word[0] is assigned to be empty, to make the constraints simple.
    pub fn assign_word_with_address(
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        cells: &Word<F>,
        word_address: &[Cell<F>],
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        // leave word[0] empty
        cells.word_mask[0].assign(region, offset, Some(F::one()))?;
        cells.word_addr_ext_0[0].assign(region, offset, Some(F::zero()))?;
        word_address[0].assign(region, offset, Some(F::zero()))?;

        for (i, item) in word_address
            .iter()
            .enumerate()
            .take(word_element_num + 1)
            .skip(1)
        {
            let op = rw_operations
                .0
                .get(op_index + i - 1)
                .ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
            item.assign(region, offset, Some(F::from(op.address() as u64)))?;
        }

        for (i, item) in word_address.iter().enumerate().skip(word_element_num + 1) {
            cells.word_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            item.assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_word_with_address_and_filter(
        region: &mut Region<'_, F>,
        offset: usize,
        rw_operations: &RWOperations<F>,
        cells: &Word<F>,
        word_address: &[Cell<F>],
        op_index: usize,
        word_element_num: usize,
        filter: RW,
    ) -> Result<(), Error> {
        let mut index = op_index;
        let mut op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        let mut i = 0;

        while i < word_element_num {
            if op.rw() == filter {
                cells.word[i].assign(region, offset, op.value().value())?;
                cells.word_mask[i].assign(region, offset, Some(F::zero()))?;
                cells.word_addr_ext_0[i].assign(
                    region,
                    offset,
                    Some(F::from(op.address_ext_0() as u64)),
                )?;
                // assign index of Locals to word_address
                word_address[i].assign(region, offset, Some(F::from(op.address() as u64)))?;

                i += 1;
            }
            index += 1;
            op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        }

        for (i, item) in word_address.iter().enumerate().skip(word_element_num) {
            cells.word_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            item.assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    pub fn assign_ref_val(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &RefVal<F>,
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        for i in 0..word_element_num.min(LEN_OF_REFERENCE_VALUE) {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.ref_val[i].assign(region, offset, op.value().value())?;
            cells.ref_val_mask[i].assign(region, offset, Some(F::zero()))?;
        }

        for i in word_element_num..LEN_OF_REFERENCE_VALUE {
            cells.ref_val_mask[i].assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }
}

pub struct AddrExt<F: FieldExt> {
    pub bytes: Vec<Cell<F>>,
}

impl<F: FieldExt> AddrExt<F> {
    pub fn assign_bytes(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        val: F,
    ) -> Result<(), Error> {
        let result_bytes: [u8; 32] = val
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in self.bytes.iter().take(MAX_ADDRESS_EXT_LENGTH).enumerate() {
            let v: u128 =
                (result_bytes[2 * index] as u128) + ((result_bytes[2 * index + 1] as u128) << 8);
            byte.assign(region, offset, Some(F::from_u128(v)))?;
        }

        Ok(())
    }

    // constraint on mask_a and mask_b
    // mask_a and mask_b is implemented to get the Nth element on addr_ext.
    pub(crate) fn constrain_mask_n(
        cb: &mut ConstraintBuilder<F>,
        mask_a: &[Cell<F>],
        mask_b: &[Cell<F>],
        n: Expression<F>,
        total_len: Expression<F>,
    ) {
        let one = Expression::Constant(F::one());

        // every entry is 0 or 1 for mask_a
        let zero_or_one = mask_a
            .iter()
            .map(|cell| {
                (
                    "zero or one",
                    (cell.expression.clone() - one.clone()) * cell.expression.clone(),
                )
            })
            .collect::<Vec<_>>();
        cb.add_constraints(zero_or_one);

        // every entry is monotonic increase
        for (i, _) in mask_a.iter().enumerate().skip(1) {
            let delta = mask_a[i].expression.clone() - mask_a[i - 1].expression.clone();
            let constraint = delta.clone() * (1.expr() - delta);
            cb.add_constraint("check header addr_ext_0", constraint);
        }

        //  sum value of mask_a is MAX_ADDRESS_EXT_LENGTH -  n
        let init = total_len.clone() - n.clone();
        let sum = mask_a
            .iter()
            .fold(init, |acc, cell| acc - cell.expression.clone());
        cb.add_constraint("read_ref_eq_0", sum);

        // sum value of mask_b is MAX_ADDRESS_EXT_LENGTH -  n - 1
        let init = total_len - n.clone() - 1.expr();
        let sum = mask_b
            .iter()
            .fold(init, |acc, cell| acc - cell.expression.clone());
        cb.add_constraint("read_ref_eq_0", sum);

        // compare mask_a and mask_b, only Nth element is different
        for (i, _) in mask_a.iter().enumerate() {
            let constraint = (n.clone() - (i as u64).expr())
                * (mask_a[i].expression.clone() - mask_b[i].expression.clone());
            cb.add_constraint("check header addr_ext_0", constraint);
        }
    }

    // bytes[n] is selected by mask_a and mask_b
    // for mask_a[n] is 1 and mask_b[n] is 0
    pub fn assign_byte_n_mask(
        region: &mut Region<'_, F>,
        offset: usize,
        mask_a: &[Cell<F>],
        mask_b: &[Cell<F>],
        n: usize,
    ) -> Result<(), Error> {
        // assign bytes mask
        for (_i, item) in mask_a.iter().enumerate().take(n) {
            item.assign(region, offset, Some(F::zero()))?;
        }
        for (_i, item) in mask_a.iter().enumerate().skip(n) {
            item.assign(region, offset, Some(F::one()))?;
        }

        for (_i, item) in mask_b.iter().enumerate().take(n + 1) {
            item.assign(region, offset, Some(F::zero()))?;
        }
        for (_i, item) in mask_b.iter().enumerate().skip(n + 1) {
            item.assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }

    pub(crate) fn location_val_constrain(
        cb: &mut ConstraintBuilder<F>,
        val_a: &[Cell<F>],
        val_b: &[Cell<F>],
    ) -> Result<(), Error> {
        let a0 = val_a
            .get(1)
            .expect("location is not exsit")
            .expression
            .clone();
        let b0 = val_b
            .get(1)
            .expect("location is not exsit")
            .expression
            .clone();
        let constraint = a0 - b0;
        cb.add_constraint("location_val_constrain: 0", constraint);

        let a1 = val_a
            .get(2)
            .expect("location is not exsit")
            .expression
            .clone();
        let b1 = val_b
            .get(2)
            .expect("location is not exsit")
            .expression
            .clone();
        let constraint = a1 - b1;
        cb.add_constraint("location_val_constrain: 1", constraint);

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn addr_ext_constrain(
        cb: &mut ConstraintBuilder<F>,
        cond: Expression<F>,
        ref_val: &[Cell<F>],
        ref_val_addr_ext_bytes: &[Cell<F>],
    ) -> Result<(), Error> {
        let ref_val_addr_ext = ref_val
            .get(2)
            .expect("addr_ext is not exsit")
            .expression
            .clone();
        let ref_val_bytes =
            FieldBytes::from(ref_val_addr_ext_bytes.to_owned()).expr_16bit(MAX_ADDRESS_EXT_LENGTH);
        let constraint = cond * (ref_val_addr_ext - ref_val_bytes);
        cb.add_constraint("borrow_field: addr_ext bytes check 0", constraint);

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn addr_ext_bytes_constrain(
        cb: &mut ConstraintBuilder<F>,
        cond: Expression<F>,
        ref_bytes: &[Cell<F>],
        ref_bytes_mask: &[Cell<F>],
        indexed_ref_bytes: &[Cell<F>],
        indexed_ref_bytes_mask: &[Cell<F>],
        offset: &Cell<F>,
    ) -> Result<(), Error> {
        // addr_ext comparation between ref_val and indexed_ref_val
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            let constraint = cond.clone()
                * (1.expr() - ref_bytes_mask[i].expression.clone())
                * (ref_bytes[i].expression.clone() - indexed_ref_bytes[i].expression.clone());
            cb.add_constraint("addr_ext_constrain: addr_ext_eq", constraint);
        }

        // field_offset is pushed into the last element of word,
        // and it's larger than the real offset by 1
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            let constraint = cond.clone()
                * ref_bytes_mask[i].expression.clone()
                * (1.expr() - indexed_ref_bytes_mask[i].expression.clone())
                * (offset.expression.clone() + 1.expr() - indexed_ref_bytes[i].expression.clone());
            cb.add_constraint("addr_ext_constrain: field_offset_eq", constraint);
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ValueHeaderGadget<F: FieldExt> {
    pub header_value: Expression<F>,
    pub flattened_len: Expression<F>,
    pub len: Expression<F>,
}

impl<F: FieldExt> ValueHeaderGadget<F> {
    pub(crate) fn construct(
        header_value: Expression<F>,
        flattened_len: Expression<F>,
        len: Expression<F>,
    ) -> Self {
        Self {
            header_value,
            flattened_len,
            len,
        }
    }
    pub(crate) fn constrain(&self, cb: &mut ConstraintBuilder<F>, name: &'static str) {
        let constraint = self.header_value.clone()
            - self.flattened_len.clone()
            - self.len.clone() * 2u64.pow(16).expr();
        cb.add_constraint(name, constraint);
    }
}
