use crate::chips::utilities::Expr;
use crate::witness::rw_operations::RW;
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
