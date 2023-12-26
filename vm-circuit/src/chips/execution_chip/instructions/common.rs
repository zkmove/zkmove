use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookup, bitwise_lookup_table::BitwiseLookup,
    bytecode_lookup_table::BytecodeLookup,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::param::MAX_ADDRESS_EXT_LENGTH;
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::utilities::{Cell, DeltaInvert, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use types::Field;

use error::{RuntimeError, StatusCode, VmResult};
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::plonk::{Error, Expression};
use itertools::izip;
use logger::prelude::*;
use movelang::utility::{decode_field_to_u256, MoveValueType, U256};
use movelang::value::{
    Value, DEPTH_OF_LOCATION_PATH, NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U32,
    NUM_OF_BYTES_U64, NUM_OF_BYTES_U8,
};
use movelang::value_ext::{
    ValueHeader, LEN_OF_REFERENCE_VALUE, LEN_OF_SIMPLE_VALUE, LOWER_FIELD_OFFSET,
    UPPER_FIELD_OFFSET,
};
use std::convert::TryInto;
use std::marker::PhantomData;

use self::word_gadget::WordCells;

pub(crate) mod generic_gadget;
pub(crate) mod reference_value_gadget;
pub(crate) mod simple_value_gadget;
pub(crate) mod value_gadget;
pub(crate) mod word_gadget;

#[derive(Clone, Debug)]
pub struct BinaryOp<F: Field> {
    pub value_a: WordCells<F>,
    pub value_b: WordCells<F>,
    pub value_c: WordCells<F>,
}

impl<F: Field> BinaryOp<F> {
    pub(crate) fn constrain_binary_op(cb: &mut ConstraintBuilder<F>, cells: &StepChipCells<F>) {
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            - 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        // Each stack push/pop have three rw_op, one is for the value header.
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + ((LEN_OF_SIMPLE_VALUE as u64) * 3).expr();
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
        binary_op.value_b.lookup_stack_pop(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );
        binary_op.value_a.lookup_stack_pop(
            cb,
            cells.stack_size.expression.clone() - 1u64.expr(),
            cells.gc.expression.clone() + (LEN_OF_SIMPLE_VALUE as u64).expr(),
        );
        binary_op.value_c.lookup_stack_push(
            cb,
            cells.stack_size.expression.clone() - 2u64.expr(),
            cells.gc.expression.clone() + ((LEN_OF_SIMPLE_VALUE * 2) as u64).expr(),
        );
    }

    pub fn assign_binary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        binary_op: &BinaryOp<F>,
    ) -> Result<(), Error> {
        // value_b
        binary_op
            .value_b
            .assign(region, offset, rw_operations, step.gc)?;
        // value_a
        binary_op
            .value_a
            .assign(region, offset, rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        // value_c
        binary_op.value_c.assign(
            region,
            offset,
            rw_operations,
            step.gc + LEN_OF_SIMPLE_VALUE * 2,
        )?;

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

        // auxiliary_1 is lower field. auxiliary_2 is upper field
        if aux_value.ty() == MoveValueType::U256 {
            let v = aux_value.value_u256().expect("should U256 value");
            cells.auxiliary_1.assign(region, offset, Some(v[1]))?;
            cells.auxiliary_2.assign(region, offset, Some(v[0]))?;
        } else {
            cells
                .auxiliary_1
                .assign(region, offset, aux_value.value())?;
            cells.auxiliary_2.assign(region, offset, Some(F::ZERO))?;
        }
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
        // every 4 bits within one cell.
        let v = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;
        let bytes = v.to_le_bytes();
        for (i, byte) in lookup_bitwise.bytes_operand_1.iter().take(64).enumerate() {
            // seperate one byte into 2 fields.
            if i % 2 == 0 {
                byte.assign(region, offset, Some(F::from((bytes[i / 2] & 0xF) as u64)))?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((bytes[i / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store operand 2 at bytes_operand_2 cell.
        // every 4 bits within one cell.
        let v = get_u256_from_op(rw_operations, step.gc)?;
        let bytes = v.to_le_bytes();
        for (i, byte) in lookup_bitwise.bytes_operand_2.iter().take(64).enumerate() {
            // seperate one byte into 2 fields
            if i % 2 == 0 {
                byte.assign(region, offset, Some(F::from((bytes[i / 2] & 0xF) as u64)))?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((bytes[i / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        // store result at bytes cell.
        // every 4 bits within one cell and cost 32 cells for upper 128 bit.
        let v = get_u256_from_op(rw_operations, step.gc + LEN_OF_SIMPLE_VALUE * 2)?;
        let bytes = v.to_le_bytes();
        for (i, byte) in lookup_bitwise.bytes.iter().take(64).enumerate() {
            // seperate one byte into 2 fields
            if i % 2 == 0 {
                byte.assign(region, offset, Some(F::from((bytes[i / 2] & 0xF) as u64)))?;
            } else {
                byte.assign(
                    region,
                    offset,
                    Some(F::from(((bytes[i / 2] & 0xF0) >> 4) as u64)),
                )?;
            }
        }

        Ok(())
    }
}

pub struct UnaryOp<F: Field> {
    pub value_a: WordCells<F>,
    pub value_c: WordCells<F>,
}

impl<F: Field> UnaryOp<F> {
    pub(crate) fn constrain_unary_op(cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cb.next.cells.stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
            + ((LEN_OF_SIMPLE_VALUE as u64) * 2).expr();
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
        unary_op.value_a.lookup_stack_pop(
            cb,
            cells.stack_size.expression.clone(),
            cells.gc.expression.clone(),
        );
        unary_op.value_c.lookup_stack_push(
            cb,
            cells.stack_size.expression.clone() - 1u64.expr(),
            cells.gc.expression.clone() + (LEN_OF_SIMPLE_VALUE as u64).expr(),
        );
    }

    pub fn assign_unary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        unary_op: &UnaryOp<F>,
    ) -> Result<(), Error> {
        // value_a
        unary_op
            .value_a
            .assign(region, offset, rw_operations, step.gc)?;
        // value_c
        unary_op
            .value_c
            .assign(region, offset, rw_operations, step.gc + LEN_OF_SIMPLE_VALUE)?;

        Ok(())
    }
}

pub struct LoadOp<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> LoadOp<F> {
    pub(crate) fn constrain_ld_op(cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let pc_expr =
            cells.pc.expression.clone() - cb.next.cells.pc.expression.clone() + 1u64.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cb.next.cells.stack_size.expression.clone()
            + 1u64.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cb.next.cells.frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cb.next.cells.gc.expression.clone()
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
    }
}

pub struct LookupBytecode<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> LookupBytecode<F> {
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
                operand2: 0u64.expr(), // reserve for upper 128 bit
                operand: bytecode_operand,
            },
        );
    }

    pub(crate) fn lookup_bytecode_u256(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,

        opcode: Opcode,
        bytecode_operand2: Expression<F>,
        bytecode_operand: Expression<F>,
    ) {
        cb.add_lookup(
            "bytecode(operand is u256) lookups",
            BytecodeLookup {
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                opcode: (opcode.index() as u64).expr(),
                operand2: bytecode_operand2,
                operand: bytecode_operand,
            },
        );
    }
}

pub struct ArithOverflow<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ArithOverflow<F> {
    pub(crate) fn constrain_range_check(
        cb: &mut ConstraintBuilder<F>,
        cells: &StepChipCells<F>,
        bytes: Vec<Cell<F>>,
        out: Expression<F>,
    ) {
        // arithmetic overflow check
        // if bytes_len = NUM_OF_BYTES_U8, then bytes_1 == out
        // else if bytes_len = NUM_OF_BYTES_U16, then bytes_2 == out
        // else if bytes_len = NUM_OF_BYTES_U32, then bytes_4 == out
        // else if bytes_len = NUM_OF_BYTES_U64, then bytes_8 == out
        // else if bytes_len = NUM_OF_BYTES_U128, then bytes_16 == out
        // fixme. u256 need range check here?
        let bytes_1 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let bytes_2 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U16);
        let bytes_4 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U32);
        let bytes_8 = FieldBytes::from(bytes.clone()).expr_with_n(NUM_OF_BYTES_U64);
        let bytes_16 = FieldBytes::from(bytes).expr_with_n(NUM_OF_BYTES_U128);

        let num_of_bytes = cells.auxiliary_1.expression.clone();
        let delta_inverse_1 = cells.auxiliary_2.expression.clone();
        let delta_inverse_2 = cells.auxiliary_3.expression.clone();
        let delta_inverse_4 = cells.auxiliary_4.expression.clone();
        let delta_inverse_8 = cells.auxiliary_5.expression.clone();
        let delta_inverse_16 = cells.auxiliary_6.expression.clone();

        let cond_1 = 1u64.expr()
            - (num_of_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr()) * delta_inverse_1;
        let cond_2 = 1u64.expr()
            - (num_of_bytes.clone() - (NUM_OF_BYTES_U16 as u64).expr()) * delta_inverse_2;
        let cond_4 = 1u64.expr()
            - (num_of_bytes.clone() - (NUM_OF_BYTES_U32 as u64).expr()) * delta_inverse_4;
        let cond_8 = 1u64.expr()
            - (num_of_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr()) * delta_inverse_8;
        let cond_16 =
            1u64.expr() - (num_of_bytes - (NUM_OF_BYTES_U128 as u64).expr()) * delta_inverse_16;

        let constraint_1 = cond_1 * (bytes_1 - out.clone());
        cb.add_constraint("range check 1", constraint_1);
        let constraint_2 = cond_2 * (bytes_2 - out.clone());
        cb.add_constraint("range check 2", constraint_2);
        let constraint_4 = cond_4 * (bytes_4 - out.clone());
        cb.add_constraint("range check 4", constraint_4);
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
        step: &ExecutionStep<F>,
        cells: &StepChipCells<F>,
        bytes: Vec<Cell<F>>,
        value: Option<F>,
    ) -> Result<(), Error> {
        // assign value into bytes
        let field = value.ok_or_else(|| {
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
        let num_of_bytes =
            Word::assign_step_value(region, offset, &step.auxiliary_1, &cells.auxiliary_1)?
                .get_lower_128();

        // assign delta_inverse(num_of_bytes, NUM_OF_BYTES_U8/U16/U32/U64/U128)
        let delta_inverse_1 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U8 as u128));
        let delta_inverse_2 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U16 as u128));
        let delta_inverse_4 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U32 as u128));
        let delta_inverse_8 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U64 as u128));
        let delta_inverse_16 =
            F::from_u128(num_of_bytes).delta_invert(F::from_u128(NUM_OF_BYTES_U128 as u128));
        cells.auxiliary_2.assign(region, offset, delta_inverse_1)?;
        cells.auxiliary_3.assign(region, offset, delta_inverse_2)?;
        cells.auxiliary_4.assign(region, offset, delta_inverse_4)?;
        cells.auxiliary_5.assign(region, offset, delta_inverse_8)?;
        cells.auxiliary_6.assign(region, offset, delta_inverse_16)?;

        Ok(())
    }
}

pub struct LookupBitwise<F: Field> {
    pub bytes: Vec<Cell<F>>,
    pub bytes_operand_1: Vec<Cell<F>>,
    pub bytes_operand_2: Vec<Cell<F>>,
}

impl<F: Field> LookupBitwise<F> {
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

pub struct Word<F: Field> {
    pub word: Vec<Cell<F>>,
    pub word_mask: Vec<Cell<F>>,
    pub word_addr_ext: Vec<Cell<F>>,
}

pub struct RefVal<F: Field> {
    pub ref_val: Vec<Cell<F>>,
    pub ref_val_mask: Vec<Cell<F>>,
}

impl<F: Field> Word<F> {
    pub fn assign_step_value(
        region: &mut Region<'_, F>,
        offset: usize,
        step_value: &Option<Value<F>>,
        cell: &Cell<F>,
    ) -> VmResult<F> {
        let value = step_value.as_ref().ok_or_else(|| {
            error!("step value {:?}", step_value);
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
        let pow2_of_val = F::from_u128(2).pow([(addr_ext_offset * 16) as u64, 0, 0, 0]);
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
        flattened_value_len: usize,
    ) -> Result<(), Error> {
        for (i, _) in cells.word.iter().enumerate().take(flattened_value_len) {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::ZERO))?;
            cells.word_addr_ext[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext() as u64)),
            )?;
        }

        for (i, _) in cells.word.iter().enumerate().skip(flattened_value_len) {
            cells.word_mask[i].assign(region, offset, Some(F::ONE))?;
            cells.word_addr_ext[i].assign(region, offset, Some(F::ZERO))?;
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
        flattened_value_len: usize,
        capacity: usize,
    ) -> Result<(), Error> {
        for i in 0..flattened_value_len {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::ZERO))?;
            cells.word_addr_ext[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext() as u64)),
            )?;
        }

        debug_assert!(flattened_value_len <= capacity);

        for i in flattened_value_len..capacity {
            cells.word_mask[i].assign(region, offset, Some(F::ONE))?;
            cells.word_addr_ext[i].assign(region, offset, Some(F::ZERO))?;
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
        flattened_value_len: usize,
    ) -> Result<(), Error> {
        // leave word[0] empty
        cells.word_mask[0].assign(region, offset, Some(F::ONE))?;
        cells.word_addr_ext[0].assign(region, offset, Some(F::ZERO))?;
        word_address[0].assign(region, offset, Some(F::ZERO))?;

        for (i, item) in word_address
            .iter()
            .enumerate()
            .take(flattened_value_len + 1)
            .skip(1)
        {
            let op = rw_operations
                .0
                .get(op_index + i - 1)
                .ok_or(Error::Synthesis)?;
            cells.word[i].assign(region, offset, op.value().value())?;
            cells.word_mask[i].assign(region, offset, Some(F::ZERO))?;
            cells.word_addr_ext[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext() as u64)),
            )?;
            item.assign(region, offset, Some(F::from(op.address() as u64)))?;
        }

        for (i, item) in word_address
            .iter()
            .enumerate()
            .skip(flattened_value_len + 1)
        {
            cells.word_mask[i].assign(region, offset, Some(F::ONE))?;
            cells.word_addr_ext[i].assign(region, offset, Some(F::ZERO))?;
            item.assign(region, offset, Some(F::ZERO))?;
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
        flattened_value_len: usize,
        filter: RW,
    ) -> Result<(), Error> {
        let mut index = op_index;
        let mut op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        let mut i = 0;

        while i < flattened_value_len {
            if op.rw() == filter {
                cells.word[i].assign(region, offset, op.value().value())?;
                cells.word_mask[i].assign(region, offset, Some(F::ZERO))?;
                cells.word_addr_ext[i].assign(
                    region,
                    offset,
                    Some(F::from(op.address_ext() as u64)),
                )?;
                // assign index of Locals to word_address
                word_address[i].assign(region, offset, Some(F::from(op.address() as u64)))?;

                i += 1;
            }
            index += 1;
            op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        }

        for (i, item) in word_address.iter().enumerate().skip(flattened_value_len) {
            cells.word_mask[i].assign(region, offset, Some(F::ONE))?;
            cells.word_addr_ext[i].assign(region, offset, Some(F::ZERO))?;
            item.assign(region, offset, Some(F::ZERO))?;
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
        flattened_value_len: usize,
    ) -> Result<(), Error> {
        for i in 0..flattened_value_len.min(LEN_OF_REFERENCE_VALUE) {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.ref_val[i].assign(region, offset, op.value().value())?;
            cells.ref_val_mask[i].assign(region, offset, Some(F::ZERO))?;
        }

        for i in flattened_value_len..LEN_OF_REFERENCE_VALUE {
            cells.ref_val_mask[i].assign(region, offset, Some(F::ONE))?;
        }

        Ok(())
    }
}

pub struct AddrExt<F: Field> {
    pub bytes: Vec<Cell<F>>,
}

impl<F: Field> AddrExt<F> {
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
        let one = Expression::Constant(F::ONE);

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
            let constraint = delta.clone() * (1u64.expr() - delta);
            cb.add_constraint("check header addr_ext", constraint);
        }

        //  sum value of mask_a is MAX_ADDRESS_EXT_LENGTH -  n
        let init = total_len.clone() - n.clone();
        let sum = mask_a
            .iter()
            .fold(init, |acc, cell| acc - cell.expression.clone());
        cb.add_constraint("read_ref_eq_0", sum);

        // sum value of mask_b is MAX_ADDRESS_EXT_LENGTH -  n - 1
        let init = total_len - n.clone() - 1u64.expr();
        let sum = mask_b
            .iter()
            .fold(init, |acc, cell| acc - cell.expression.clone());
        cb.add_constraint("read_ref_eq_0", sum);

        // compare mask_a and mask_b, only Nth element is different
        for (i, _) in mask_a.iter().enumerate() {
            let constraint = (n.clone() - (i as u64).expr())
                * (mask_a[i].expression.clone() - mask_b[i].expression.clone());
            cb.add_constraint("check header addr_ext", constraint);
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
            item.assign(region, offset, Some(F::ZERO))?;
        }
        for (_i, item) in mask_a.iter().enumerate().skip(n) {
            item.assign(region, offset, Some(F::ONE))?;
        }

        for (_i, item) in mask_b.iter().enumerate().take(n + 1) {
            item.assign(region, offset, Some(F::ZERO))?;
        }
        for (_i, item) in mask_b.iter().enumerate().skip(n + 1) {
            item.assign(region, offset, Some(F::ONE))?;
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
                * (1u64.expr() - ref_bytes_mask[i].expression.clone())
                * (ref_bytes[i].expression.clone() - indexed_ref_bytes[i].expression.clone());
            cb.add_constraint("addr_ext_constrain: addr_ext_eq", constraint);
        }

        // field_offset is pushed into the last element of word,
        // and it's larger than the real offset by 1
        for i in 0..MAX_ADDRESS_EXT_LENGTH {
            let constraint = cond.clone()
                * ref_bytes_mask[i].expression.clone()
                * (1u64.expr() - indexed_ref_bytes_mask[i].expression.clone())
                * (offset.expression.clone() + 1u64.expr()
                    - indexed_ref_bytes[i].expression.clone());
            cb.add_constraint("addr_ext_constrain: field_offset_eq", constraint);
        }

        Ok(())
    }
}
// TODO: merge with the struct HeaderCells below
#[derive(Clone, Debug)]
pub struct ValueHeaderGadget<F: Field> {
    pub header_value: Expression<F>,
    pub flattened_len: Expression<F>,
    pub len: Expression<F>,
}

impl<F: Field> ValueHeaderGadget<F> {
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

#[derive(Clone, Debug)]
pub(crate) struct HeaderCells<F> {
    // should align with ValueHeader
    pub(crate) flattened_len: Cell<F>,
    pub(crate) len: Cell<F>,
}

impl<F: Field> HeaderCells<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        // alloc cell
        let flattened_len = cb.alloc_cell();
        let len = cb.alloc_cell();

        Self { flattened_len, len }
    }
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        header_value: F,
    ) -> Result<(), Error> {
        let (flattened_len, len) = ValueHeader::from(header_value).members();
        self.flattened_len
            .assign(region, offset, Some(F::from(flattened_len as u64)))?;
        self.len.assign(region, offset, Some(F::from(len as u64)))?;

        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) fn header_value_parse<F: Field>(
    rw_operations: &RWOperations<F>,
    op_index: usize,
) -> Result<(usize, usize), Error> {
    let header_value = get_field_from_op(rw_operations, op_index)?;
    let flattened_len = (header_value.get_lower_128() & 0xFFFF) as usize;
    let len = ((header_value.get_lower_128() & 0xFFFF0000) >> 16) as usize;
    Ok((flattened_len, len))
}

#[allow(dead_code)]
pub(crate) fn get_field_from_op<F: Field>(
    rw_operations: &RWOperations<F>,
    op_index: usize,
) -> Result<F, Error> {
    let op = rw_operations.0.get(op_index).ok_or(Error::Synthesis)?;
    let v = op.value().value().ok_or_else(|| {
        error!("field is None");
        Error::Synthesis
    })?;
    Ok(v)
}

pub(crate) fn get_u256_from_op<F: Field>(
    rw_operations: &RWOperations<F>,
    op_index: usize,
) -> Result<U256, Error> {
    let upper = get_field_from_op(rw_operations, op_index + UPPER_FIELD_OFFSET)?;
    let lower = get_field_from_op(rw_operations, op_index + LOWER_FIELD_OFFSET)?;
    let v = decode_field_to_u256(&[upper, lower]);
    Ok(v)
}

pub(crate) fn get_u256_from_value<F: Field>(value: Value<F>) -> Result<U256, Error> {
    if value.ty() == MoveValueType::U256 {
        let f = value.value_u256().unwrap();
        Ok(decode_field_to_u256(&f))
    } else {
        let v = value
            .value()
            .ok_or_else(|| {
                error!("upper field is None");
                Error::Synthesis
            })?
            .get_lower_128();
        let v = U256::from(v);
        Ok(v)
    }
}
