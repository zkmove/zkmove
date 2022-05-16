// Copyright (c) zkMove Authors

use crate::chips::utilities::Expr;
use crate::circuit_inputs::rw_operations::RW;
use halo2_proofs::plonk::{Advice, Column, Expression};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct RWTable {
    pub gc_column: Column<Advice>,
    pub rw_target_column: Column<Advice>,
    pub rw_column: Column<Advice>,
    pub call_index_column: Column<Advice>,
    pub address_column: Column<Advice>,
    pub value_column: Column<Advice>,
}
pub const RW_LOOKUP_TABLE_WIDTH: usize = 6;

impl RWTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        RWTable {
            gc_column: meta.advice_column(),
            rw_target_column: meta.advice_column(),
            rw_column: meta.advice_column(),
            call_index_column: meta.advice_column(),
            address_column: meta.advice_column(),
            value_column: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        let mut columns = vec![];
        columns.push(self.gc_column);
        columns.push(self.rw_target_column);
        columns.push(self.rw_column);
        columns.push(self.call_index_column);
        columns.push(self.address_column);
        columns.push(self.value_column);
        columns
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWTarget {
    Stack = 0,
    Locals,
}

pub struct RWLookup<F: FieldExt> {
    pub gc: Expression<F>,         // global counter
    pub rw_target: Expression<F>,  // RWTarget
    pub rw: Expression<F>,         // read or write
    pub call_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,    // locals index, or stack address
    pub value: Expression<F>,
}

impl<F: FieldExt> RWLookup<F> {
    pub fn stack_push(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            call_index: 0.expr(),
            address: stack_size,
            value,
        }
    }

    pub fn stack_pop(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::READ as u64).expr(),
            call_index: 0.expr(),
            address: stack_size - 1.expr(),
            value,
        }
    }

    pub fn locals_copy(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                call_index,
                address: locals_index,
                value: value.clone(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value,
            },
        )
    }

    pub fn locals_move(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                call_index: call_index.clone(),
                address: locals_index.clone(),
                value: value.clone(),
            },
            RWLookup {
                gc: gc.clone() + 1.expr(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index,
                address: locals_index,
                value: 0.expr(), // todo: is it ok to use 0 for Value::Invalid?
            },
            RWLookup {
                gc: gc + 2.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value,
            },
        )
    }

    pub fn locals_store(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::READ as u64).expr(),
                call_index: 0.expr(),
                address: stack_size - 1.expr(),
                value: value.clone(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index,
                address: locals_index,
                value,
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: Column<Advice>,
    pub function_index_column: Column<Advice>,
    pub pc_column: Column<Advice>,
    pub opcode_column: Column<Advice>,
    pub operand_column: Column<Advice>,
}
pub const BYTECODE_LOOKUP_TABLE_WIDTH: usize = 5;

impl BytecodeLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        BytecodeLookupTable {
            module_index_column: meta.advice_column(),
            function_index_column: meta.advice_column(),
            pc_column: meta.advice_column(),
            opcode_column: meta.advice_column(),
            operand_column: meta.advice_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        let mut columns = vec![];
        columns.push(self.module_index_column);
        columns.push(self.function_index_column);
        columns.push(self.pc_column);
        columns.push(self.opcode_column);
        columns.push(self.operand_column);
        columns
    }
}

pub struct BytecodeLookup<F: FieldExt> {
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub opcode: Expression<F>,
    pub operand: Expression<F>,
}
