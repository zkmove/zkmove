use crate::chips::utilities::Expr;
use crate::witness::rw_operations::RW;
use halo2_proofs::plonk::{Advice, Column, Expression, VirtualCells};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Debug)]
pub struct RWTable {
    pub gc_column: Column<Advice>,
    pub rw_target_column: Column<Advice>,
    pub rw_column: Column<Advice>,
    pub frame_index_column: Column<Advice>,
    pub address_column: Column<Advice>,
    pub address_ext_0_column: Column<Advice>,
    pub value_column: Column<Advice>,
    pub sd_index_column: Column<Advice>,
}
pub const RW_LOOKUP_TABLE_WIDTH: usize = 9;

impl RWTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_table = RWTable {
            gc_column: meta.advice_column(),
            rw_target_column: meta.advice_column(),
            rw_column: meta.advice_column(),
            frame_index_column: meta.advice_column(),
            address_column: meta.advice_column(),
            address_ext_0_column: meta.advice_column(),
            value_column: meta.advice_column(),
            sd_index_column: meta.advice_column(),
        };

        // rw_table will be copied to memory chip
        meta.enable_equality(rw_table.gc_column);
        meta.enable_equality(rw_table.rw_target_column);
        meta.enable_equality(rw_table.rw_column);
        meta.enable_equality(rw_table.frame_index_column);
        meta.enable_equality(rw_table.address_column);
        meta.enable_equality(rw_table.address_ext_0_column);
        meta.enable_equality(rw_table.value_column);
        meta.enable_equality(rw_table.sd_index_column);

        rw_table
    }

    /// Return the list of expressions used to define the lookup table.
    /// TODO: abstract it into a trait
    pub fn table_exprs<F: FieldExt>(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.gc_column,
            self.rw_target_column,
            self.rw_column,
            self.frame_index_column,
            self.address_column,
            self.address_ext_0_column,
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

#[derive(Clone, Debug)]
pub struct RWLookup<F: FieldExt> {
    pub gc: Expression<F>,          // global counter
    pub rw_target: Expression<F>,   // RWTarget
    pub rw: Expression<F>,          // read or write
    pub frame_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,     // locals index, stack address, or global account address
    pub address_ext_0: Expression<F>,
    pub value: Expression<F>,
    pub sd_index: Expression<F>, // struct definition index used by global rw ops
}
impl<F: FieldExt> RWLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.gc.clone(),
            self.rw_target.clone(),
            self.rw.clone(),
            self.frame_index.clone(),
            self.address.clone(),
            self.address_ext_0.clone(),
            self.value.clone(),
            self.sd_index.clone(),
        ]
    }
}

impl<F: FieldExt> RWLookup<F> {
    pub fn stack_push(
        gc: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: 0.expr(),
            address: stack_size,
            address_ext_0,
            value,
            sd_index: 0.expr(),
        }
    }

    pub fn stack_pop(
        gc: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index: 0.expr(),
            address: stack_size - 1.expr(),
            address_ext_0,
            value,
            sd_index: 0.expr(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_copy(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
        word_element_num: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext_0: address_ext_0.clone(),
                value: value.clone(),
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + word_element_num,
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0.expr(),
                address: stack_size,
                address_ext_0,
                value,
                sd_index: 0.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_move(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
        word_element_num: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: frame_index.clone(),
                address: locals_index.clone(),
                address_ext_0: address_ext_0.clone(),
                value: value.clone(),
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc.clone() + word_element_num.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext_0: address_ext_0.clone(),
                value: 0.expr(),
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + word_element_num * 2.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0.expr(),
                address: stack_size,
                address_ext_0,
                value,
                sd_index: 0.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_store(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
        word_element_num: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0.expr(),
                address: stack_size - 1.expr(),
                address_ext_0: address_ext_0.clone(),
                value: value.clone(),
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + word_element_num,
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext_0,
                value,
                sd_index: 0.expr(),
            },
        )
    }

    pub fn locals_read(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index,
            address: locals_index,
            address_ext_0,
            value,
            sd_index: 0.expr(),
        }
    }

    pub fn locals_write(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index,
            address: locals_index,
            address_ext_0,
            value,
            sd_index: 0.expr(),
        }
    }

    pub fn global_write(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
        address_ext_0: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: 0.expr(),
            address,
            address_ext_0,
            value,
            sd_index,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn move_from_global_to_stack(
        gc: Expression<F>,
        global_address: Expression<F>,
        sd_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
        word_element_num: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0.expr(),
                address: global_address.clone(),
                sd_index: sd_index.clone(),
                address_ext_0: address_ext_0.clone(),
                value: value.clone(),
            },
            RWLookup {
                gc: gc.clone() + word_element_num.clone(),
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0.expr(),
                address: global_address,
                sd_index,
                address_ext_0: address_ext_0.clone(),
                value: 0.expr(),
            },
            RWLookup {
                gc: gc + word_element_num * 2.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0.expr(),
                address: stack_size - 1.expr(),
                address_ext_0,
                value,
                sd_index: 0.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn move_to_global(
        gc: Expression<F>,
        stack_size: Expression<F>,
        global_address: Expression<F>,
        sd_index: Expression<F>,
        address_ext_0: Expression<F>,
        value: Expression<F>,
        word_elem_num: Expression<F>,
        depth_of_addr_path: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0.expr(),
                address: stack_size - 1.expr(),
                address_ext_0: address_ext_0.clone(),
                value: value.clone(),
                sd_index: 0.expr(),
            },
            RWLookup {
                gc: gc + depth_of_addr_path + word_elem_num, // + depth_of_addr_path, because, in the middle, a signer reference is popped.
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0.expr(),
                address: global_address,
                sd_index,
                address_ext_0,
                value,
            },
        )
    }

    pub fn global_read(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
        address_ext_0: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index: 0.expr(),
            address,
            address_ext_0,
            value,
            sd_index,
        }
    }
}
