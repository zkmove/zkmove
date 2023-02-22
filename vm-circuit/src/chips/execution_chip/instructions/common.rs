use crate::chips::execution_chip::lookup_tables::{
    arith_op_lookup_table::ArithOpLookup, bitwise_lookup_table::BitwiseLookup,
    bytecode_lookup_table::BytecodeLookup, rw_table::RWLookup,
};
use crate::chips::execution_chip::opcode::Opcode;
use crate::chips::execution_chip::step_chip::{StepChipCells, WORD_CAPACITY};
use crate::chips::utilities::{DeltaInvert, Expr, FieldBytes};
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::{RWOperations, RW};
use halo2_proofs::arithmetic::FieldExt;

use error::VmResult;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use itertools::izip;
use logger::prelude::*;
use movelang::value::{Value, NUM_OF_BYTES_U128, NUM_OF_BYTES_U64, NUM_OF_BYTES_U8};
use std::convert::TryInto;
use std::marker::PhantomData;

pub struct BinaryOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BinaryOp<F> {
    pub fn constrain_binary_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 3.expr();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond * func_index),
        ]);
    }

    pub fn lookup_binary_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                cells.value_b.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                0.expr(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 2.expr(),
                0.expr(),
                0.expr(),
                cells.value_c.expression.clone(),
            ),
            cond,
        ));
    }

    pub fn assign_binary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_b.assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_c.assign(region, offset, op.value().value())?;

        Ok(())
    }

    pub fn assign_binary_op_with_auxiliary(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        Self::assign_binary_op(region, offset, step, rw_operations, cells)?;

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
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        // store operand 1 at bytes_operand_1 cell.
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
        for (index, byte) in cells.bytes_operand_1.iter().take(16).enumerate() {
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
            .get(step.gc)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes_operand_2.iter().take(16).enumerate() {
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
            .get(step.gc + 2)
            .ok_or(Error::Synthesis)?
            .value()
            .value()
            .ok_or(Error::Synthesis)?;
        let result_bytes: [u8; 32] = result
            .to_repr()
            .as_ref()
            .try_into()
            .expect("Field fits into 256 bits");
        for (index, byte) in cells.bytes.iter().take(16).enumerate() {
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
    _marker: PhantomData<F>,
}

impl<F: FieldExt> UnaryOp<F> {
    pub fn constrain_unary_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr =
            cells.stack_size.expression.clone() - cells.next_stack_size.expression.clone();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 2.expr();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond * func_index),
        ]);
    }

    pub fn lookup_unary_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                0.expr(),
                0.expr(),
                cells.value_c.expression.clone(),
            ),
            cond,
        ));
    }

    pub fn assign_unary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_operations.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        let op = rw_operations.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_c.assign(region, offset, op.value().value())?;

        Ok(())
    }
}

pub struct LoadOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LoadOp<F> {
    pub fn constrain_ld_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let frame_index_expr =
            cells.frame_index.expression.clone() - cells.next_frame_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();
        let module_index =
            cells.module_index.expression.clone() - cells.next_module_index.expression.clone();
        let func_index =
            cells.function_index.expression.clone() - cells.next_function_index.expression.clone();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("frame index", cond.clone() * frame_index_expr),
            ("gc", cond.clone() * gc_expr),
            ("module index", cond.clone() * module_index),
            ("function index", cond * func_index),
        ]);
    }

    pub fn lookup_ld_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                0.expr(),
                0.expr(),
                cells.value_a.expression.clone(),
            ),
            cond,
        ));
    }
}

pub struct LookupBytecode<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LookupBytecode<F> {
    pub fn lookup_bytecode(
        cells: &StepChipCells<F>,
        opcode: Opcode,
        bytecode_operand: Expression<F>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        bytecode_lookups.push((
            BytecodeLookup {
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                opcode: (opcode.index() as u64).expr(),
                operand: bytecode_operand,
            },
            cond,
        ));
    }
}

pub struct ArithOverflow<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ArithOverflow<F> {
    pub fn constrain_range_check(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
        out: Expression<F>,
    ) {
        // arithmetic overflow check
        // if bytes_len = NUM_OF_BYTES_U8, then bytes_1 == out
        // else if bytes_len = NUM_OF_BYTES_U64, then bytes_8 == out
        // else if bytes_len = NUM_OF_BYTES_U128, then bytes_16 == out
        let bytes_1 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U8);
        let bytes_8 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U64);
        let bytes_16 = FieldBytes::from(cells.bytes.clone()).expr_with_n(NUM_OF_BYTES_U128);

        let num_of_bytes = cells.auxiliary_1.expression.clone();
        let delta_inverse_1 = cells.auxiliary_2.expression.clone();
        let delta_inverse_8 = cells.auxiliary_3.expression.clone();
        let delta_inverse_16 = cells.auxiliary_4.expression.clone();

        let cond_1 = cond.clone()
            * (1.expr()
                - (num_of_bytes.clone() - (NUM_OF_BYTES_U8 as u64).expr()) * delta_inverse_1);
        let cond_8 = cond.clone()
            * (1.expr()
                - (num_of_bytes.clone() - (NUM_OF_BYTES_U64 as u64).expr()) * delta_inverse_8);
        let cond_16 = cond
            * (1.expr() - (num_of_bytes - (NUM_OF_BYTES_U128 as u64).expr()) * delta_inverse_16);

        let constraint_1 = cond_1 * (bytes_1 - out.clone());
        constraints.push(("range check 1", constraint_1));
        let constraint_8 = cond_8 * (bytes_8 - out.clone());
        constraints.push(("range check 8", constraint_8));
        let constraint_16 = cond_16 * (bytes_16 - out);
        constraints.push(("range check 16", constraint_16));
    }

    // lookup (module_index, function_index, pc, num_of_bytes) in the arith op table.
    pub fn lookup_arith_op(
        cells: &StepChipCells<F>,
        arith_op_lookups: &mut Vec<(ArithOpLookup<F>, Expression<F>)>,
        cond: Expression<F>,
        num_of_bytes: Expression<F>,
    ) {
        arith_op_lookups.push((
            ArithOpLookup {
                module_index: cells.module_index.expression.clone(),
                function_index: cells.function_index.expression.clone(),
                pc: cells.pc.expression.clone(),
                num_of_bytes,
            },
            cond,
        ));
    }

    // given a value, assign it's number of bytes (num_of_bytes) into auxiliary_1
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U8 into auxiliary_2
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U64 into auxiliary_3
    // assign delta_inverse of num_of_bytes and NUM_OF_BYTES_U128 into auxiliary_4
    pub fn assign_num_of_bytes(
        region: &mut Region<'_, F>,
        offset: usize,
        cells: &StepChipCells<F>,
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
        for (index, byte) in cells.bytes.iter().enumerate() {
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
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LookupBitwise<F> {
    pub fn lookup_bitwise(
        cells: &StepChipCells<F>,
        opcode: Opcode,
        bitwise_lookups: &mut Vec<(BitwiseLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        for (operand_1, operand_2, result_value) in
            izip!(&cells.bytes_operand_1, &cells.bytes_operand_2, &cells.bytes)
        {
            bitwise_lookups.push((
                BitwiseLookup {
                    opcode: (opcode.index() as u64).expr(),
                    value_1: operand_1.expression.clone(),
                    value_2: operand_2.expression.clone(),
                    result: result_value.expression.clone(),
                },
                cond.clone(),
            ));
        }
    }
}

pub struct Word<F: FieldExt> {
    _marker: PhantomData<F>,
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

    pub fn assign_word_a(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        // fixme: word_element_num may be large than WORD_CAPACITY
        for i in 0..word_element_num {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word_a[i].assign(region, offset, op.value().value())?;
            cells.word_a_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_a_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
            cells.word_a_addr_ext_1[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_1() as u64)),
            )?;
        }

        for i in word_element_num..WORD_CAPACITY {
            cells.word_a_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_a_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            cells.word_a_addr_ext_1[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    pub fn assign_word_b(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        // fixme: word_element_num may be large than WORD_CAPACITY
        for i in 0..word_element_num {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word_b[i].assign(region, offset, op.value().value())?;
            cells.word_b_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_b_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
            cells.word_b_addr_ext_1[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_1() as u64)),
            )?;
        }

        for i in word_element_num..WORD_CAPACITY {
            cells.word_b_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_b_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            cells.word_b_addr_ext_1[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    pub fn assign_word_b_with_address(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
        op_index: usize,
        word_element_num: usize,
    ) -> Result<(), Error> {
        for i in 0..word_element_num {
            let op = rw_operations.0.get(op_index + i).ok_or(Error::Synthesis)?;
            cells.word_b[i].assign(region, offset, op.value().value())?;
            cells.word_b_mask[i].assign(region, offset, Some(F::zero()))?;
            cells.word_b_addr_ext_0[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_0() as u64)),
            )?;
            cells.word_b_addr_ext_1[i].assign(
                region,
                offset,
                Some(F::from(op.address_ext_1() as u64)),
            )?;
            cells.word_address[i].assign(region, offset, Some(F::from(op.address() as u64)))?;
        }

        for i in word_element_num..WORD_CAPACITY {
            cells.word_b_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_b_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            cells.word_b_addr_ext_1[i].assign(region, offset, Some(F::zero()))?;
            cells.word_address[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_word_b_with_address_and_filter(
        region: &mut Region<'_, F>,
        offset: usize,
        _step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
        op_index: usize,
        word_element_num: usize,
        filter: RW,
    ) -> Result<(), Error> {
        let mut index = op_index;
        let mut op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        let mut i = 0;

        while i < word_element_num {
            if op.rw() == filter {
                cells.word_b[i].assign(region, offset, op.value().value())?;
                cells.word_b_mask[i].assign(region, offset, Some(F::zero()))?;
                cells.word_b_addr_ext_0[i].assign(
                    region,
                    offset,
                    Some(F::from(op.address_ext_0() as u64)),
                )?;
                cells.word_b_addr_ext_1[i].assign(
                    region,
                    offset,
                    Some(F::from(op.address_ext_1() as u64)),
                )?;
                // assign index of Locals to word_address
                cells.word_address[i].assign(region, offset, Some(F::from(op.address() as u64)))?;

                i += 1;
            }
            index += 1;
            op = rw_operations.0.get(index).ok_or(Error::Synthesis)?;
        }

        for i in word_element_num..WORD_CAPACITY {
            cells.word_b_mask[i].assign(region, offset, Some(F::one()))?;
            cells.word_b_addr_ext_0[i].assign(region, offset, Some(F::zero()))?;
            cells.word_b_addr_ext_1[i].assign(region, offset, Some(F::zero()))?;
            cells.word_address[i].assign(region, offset, Some(F::zero()))?;
        }

        Ok(())
    }
}
