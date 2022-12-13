// Copyright (c) zkMove Authors

use crate::chips::utilities::Expr;
use crate::witness::rw_operations::RW;
use halo2_proofs::plonk::{Advice, Column, Expression, TableColumn};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct RWTable {
    pub gc_column: Column<Advice>,
    pub rw_target_column: Column<Advice>,
    pub rw_column: Column<Advice>,
    pub call_index_column: Column<Advice>,
    pub address_column: Column<Advice>,
    pub value_column: Column<Advice>,
    pub sd_index_column: Column<Advice>,
}
pub const RW_LOOKUP_TABLE_WIDTH: usize = 7;

impl RWTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_table = RWTable {
            gc_column: meta.advice_column(),
            rw_target_column: meta.advice_column(),
            rw_column: meta.advice_column(),
            call_index_column: meta.advice_column(),
            address_column: meta.advice_column(),
            value_column: meta.advice_column(),
            sd_index_column: meta.advice_column(),
        };

        // rw_table will be copied to memory chip
        meta.enable_equality(rw_table.gc_column);
        meta.enable_equality(rw_table.rw_target_column);
        meta.enable_equality(rw_table.rw_column);
        meta.enable_equality(rw_table.call_index_column);
        meta.enable_equality(rw_table.address_column);
        meta.enable_equality(rw_table.value_column);
        meta.enable_equality(rw_table.sd_index_column);

        rw_table
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.gc_column,
            self.rw_target_column,
            self.rw_column,
            self.call_index_column,
            self.address_column,
            self.value_column,
            self.sd_index_column,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWTarget {
    Stack = 0,
    Locals,
    Global,
}

pub struct RWLookup<F: FieldExt> {
    pub gc: Expression<F>,         // global counter
    pub rw_target: Expression<F>,  // RWTarget
    pub rw: Expression<F>,         // read or write
    pub call_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,    // locals index, stack address, or global account address
    pub value: Expression<F>,
    pub sd_index: Expression<F>, // struct definition index used by global rw ops
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
            sd_index: 0.expr(),
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
            sd_index: 0.expr(),
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
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value,
                sd_index: 0.expr(),
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
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc.clone() + 1.expr(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index,
                address: locals_index,
                value: 0.expr(), // todo: is it ok to use 0 for Value::Invalid?
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + 2.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value,
                sd_index: 0.expr(),
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
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index,
                address: locals_index,
                value,
                sd_index: 0.expr(),
            },
        )
    }

    pub fn locals_ref(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
        reference_index: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                call_index,
                address: locals_index,
                value,
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value: reference_index,
                sd_index: 0.expr(),
            },
        )
    }

    pub fn locals_read_ref(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::READ as u64).expr(),
            call_index,
            address: locals_index,
            value,
            sd_index: 0.expr(),
        }
    }

    pub fn locals_write_ref(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            call_index,
            address: locals_index,
            value,
            sd_index: 0.expr(),
        }
    }

    pub fn global_write(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            call_index: 0.expr(),
            address,
            value,
            sd_index,
        }
    }

    pub fn global_read(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::READ as u64).expr(),
            call_index: 0.expr(),
            address,
            value,
            sd_index,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BytecodeLookupTable {
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub opcode_column: TableColumn,
    pub operand_column: TableColumn,
}
pub const BYTECODE_LOOKUP_TABLE_WIDTH: usize = 5;

impl BytecodeLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        BytecodeLookupTable {
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            opcode_column: meta.lookup_table_column(),
            operand_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.opcode_column,
            self.operand_column,
        ]
    }
}

pub struct BytecodeLookup<F: FieldExt> {
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub opcode: Expression<F>,
    pub operand: Expression<F>,
}

#[derive(Clone, Debug)]
pub struct CallLookupTable {
    pub type_column: TableColumn,
    pub module_index_column: TableColumn,
    pub function_index_column: TableColumn,
    pub pc_column: TableColumn,
    pub callee_module_index_column: TableColumn,
    pub callee_function_index_column: TableColumn,
    pub next_pc_column: TableColumn,
}

pub const CALL_LOOKUP_TABLE_WIDTH: usize = 7;

impl CallLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        CallLookupTable {
            type_column: meta.lookup_table_column(),
            module_index_column: meta.lookup_table_column(),
            function_index_column: meta.lookup_table_column(),
            pc_column: meta.lookup_table_column(),
            callee_module_index_column: meta.lookup_table_column(),
            callee_function_index_column: meta.lookup_table_column(),
            next_pc_column: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.type_column,
            self.module_index_column,
            self.function_index_column,
            self.pc_column,
            self.callee_module_index_column,
            self.callee_function_index_column,
            self.next_pc_column,
        ]
    }
}

pub struct CallLookup<F: FieldExt> {
    pub type_: Expression<F>,
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub next_module_index: Expression<F>,
    pub next_function_index: Expression<F>,
    pub next_pc: Expression<F>,
}

pub struct LookupsWithCondition<F: FieldExt> {
    pub rw_lookups: Vec<(RWLookup<F>, /*condition*/ Expression<F>)>,
    pub bytecode_lookups: Vec<(BytecodeLookup<F>, /*condition*/ Expression<F>)>,
    pub call_lookups: Vec<(CallLookup<F>, /*condition*/ Expression<F>)>,
}

impl<F: FieldExt> LookupsWithCondition<F> {
    pub fn new() -> Self {
        Self {
            rw_lookups: Vec::new(),
            bytecode_lookups: Vec::new(),
            call_lookups: Vec::new(),
        }
    }
}

impl<F: FieldExt> Default for LookupsWithCondition<F> {
    fn default() -> Self {
        Self::new()
    }
}
