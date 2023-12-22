use crate::chips::utilities::Expr;
use crate::witness::rw_operations::ConvertedRWOperation;
use crate::witness::rw_operations::RWOperations;
use crate::witness::rw_operations::RW;
use crate::witness::CircuitConfig;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::circuit::Region;
use halo2_base::halo2_proofs::circuit::Value as CircuitValue;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::plonk::{Advice, Column, Error, Expression, VirtualCells};
use halo2_base::halo2_proofs::poly::Rotation;
use logger::prelude::{debug, error};
use types::Field;

#[derive(Clone, Debug)]
pub struct RWTable {
    pub gc_column: Column<Advice>,
    pub rw_target_column: Column<Advice>,
    pub rw_column: Column<Advice>,
    pub frame_index_column: Column<Advice>,
    pub address_column: Column<Advice>,
    pub address_ext_column: Column<Advice>,
    pub value_column: Column<Advice>,
    pub sd_index_column: Column<Advice>,
}
pub const RW_LOOKUP_TABLE_WIDTH: usize = 9;

impl RWTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_table = RWTable {
            gc_column: meta.advice_column(),
            rw_target_column: meta.advice_column(),
            rw_column: meta.advice_column(),
            frame_index_column: meta.advice_column(),
            address_column: meta.advice_column(),
            address_ext_column: meta.advice_column(),
            value_column: meta.advice_column(),
            sd_index_column: meta.advice_column(),
        };

        // rw_table will be copied to memory chip
        meta.enable_equality(rw_table.gc_column);
        meta.enable_equality(rw_table.rw_target_column);
        meta.enable_equality(rw_table.rw_column);
        meta.enable_equality(rw_table.frame_index_column);
        meta.enable_equality(rw_table.address_column);
        meta.enable_equality(rw_table.address_ext_column);
        meta.enable_equality(rw_table.value_column);
        meta.enable_equality(rw_table.sd_index_column);

        rw_table
    }

    /// Return the list of expressions used to define the lookup table.
    /// TODO: abstract it into a trait
    pub fn table_exprs<F: Field>(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
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
            self.address_ext_column,
            self.value_column,
            self.sd_index_column,
        ]
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rw_operations: RWOperations,
        circuit_config: &CircuitConfig,
    ) -> Result<
        (
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
            Vec<ConvertedRWOperation<F>>,
        ),
        Error,
    > {
        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) = rw_operations.into();
        let mut stack_operations: Vec<ConvertedRWOperation<F>> = (&sorted_stack_ops).into();
        let mut locals_operations: Vec<ConvertedRWOperation<F>> = (&sorted_locals_ops).into();
        let mut global_operations: Vec<ConvertedRWOperation<F>> = (&sorted_global_ops).into();
        let stack_ops_num = circuit_config.stack_ops_num.unwrap_or(0);
        let locals_ops_num = circuit_config.locals_ops_num.unwrap_or(0);
        let global_ops_num = circuit_config.global_ops_num.unwrap_or(0);
        debug!(
            "rw_lens, stack: {}, local: {}, global: {}",
            stack_operations.len(),
            locals_operations.len(),
            global_operations.len()
        );
        if stack_ops_num > 0 {
            if stack_operations.len() > stack_ops_num {
                error!(
                    "stack operations length {:?} exceeds stack_ops_num {:?}",
                    stack_operations.len(),
                    stack_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                stack_operations.resize(stack_ops_num, ConvertedRWOperation::empty());
            }
        }
        if locals_ops_num > 0 {
            if locals_operations.len() > locals_ops_num {
                error!(
                    "locals operations length {:?} exceeds locals_ops_num {:?}",
                    locals_operations.len(),
                    locals_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                locals_operations.resize(locals_ops_num, ConvertedRWOperation::empty());
            }
        }
        if global_ops_num > 0 {
            if global_operations.len() > global_ops_num {
                error!(
                    "global operations length {:?} exceeds global_ops_num {:?}",
                    global_operations.len(),
                    global_ops_num
                );
                return Err(Error::Synthesis);
            } else {
                global_operations.resize(global_ops_num, ConvertedRWOperation::empty());
            }
        }
        for (column_idx, column) in self.columns().into_iter().enumerate() {
            layouter.assign_region(
                || format!("rw_table[{}]", column_idx),
                |mut region| {
                    region.assign_advice(
                        || format!("rw_table[{}][0]", column_idx),
                        column,
                        0,
                        || CircuitValue::known(F::ZERO),
                    )?;

                    // assign stack operations
                    Self::assign_rw_ops(&mut region, column_idx, column, 0, &mut stack_operations)?;
                    // assign locals operations after stack operations
                    Self::assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len(),
                        &mut locals_operations,
                    )?;
                    // assign global operations after locals operations
                    Self::assign_rw_ops(
                        &mut region,
                        column_idx,
                        column,
                        stack_operations.len() + locals_operations.len(),
                        &mut global_operations,
                    )
                },
            )?;
        }

        Ok((stack_operations, locals_operations, global_operations))
    }

    #[allow(clippy::manual_try_fold)]
    pub(crate) fn assign_rw_ops<F: Field>(
        region: &mut Region<'_, F>,
        column_idx: usize,
        column: Column<Advice>,
        offset: usize,
        rw_operations: &mut Vec<ConvertedRWOperation<F>>,
    ) -> Result<(), Error> {
        (0..rw_operations.len())
            .map(|i| {
                let op = rw_operations.get_mut(i).ok_or_else(|| {
                    error!("get rw operation error");
                    Error::Synthesis
                })?;
                let field = op.get_field(column_idx).map_err(|e| {
                    error!("get field failed: {:?}", e);
                    Error::Synthesis
                })?;

                let cell = region.assign_advice(
                    || format!("rw_table[{}][{}]", column_idx, offset + i + 1),
                    column,
                    offset + i + 1,
                    || CircuitValue::known(field),
                )?;
                op.assign_cell(column_idx, Some(cell)).map_err(|e| {
                    error!("assign cell failed: {:?}", e);
                    Error::Synthesis
                })
            })
            .try_fold((), |_, res| res)
    }

    // NOTICE: table height must be consistent with assign_table()
    pub fn tables_height(
        &self,
        rw_operations: RWOperations,
        circuit_config: &CircuitConfig,
    ) -> usize {
        let (sorted_stack_ops, sorted_locals_ops, sorted_global_ops) = rw_operations.into();

        let stack_ops_num = circuit_config
            .stack_ops_num
            .unwrap_or(0)
            .max(sorted_stack_ops.0.len());
        let locals_ops_num = circuit_config
            .locals_ops_num
            .unwrap_or(0)
            .max(sorted_locals_ops.0.len());
        let global_ops_num = circuit_config
            .global_ops_num
            .unwrap_or(0)
            .max(sorted_global_ops.0.len());

        stack_ops_num + locals_ops_num + global_ops_num + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWTarget {
    Stack = 0,
    Locals,
    Global,
}

#[derive(Clone, Debug)]
pub struct RWLookup<F: Field> {
    pub gc: Expression<F>,          // global counter
    pub rw_target: Expression<F>,   // RWTarget
    pub rw: Expression<F>,          // read or write
    pub frame_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,     // locals index, stack address, or global account address
    pub address_ext: Expression<F>,
    pub value: Expression<F>,
    pub sd_index: Expression<F>, // struct definition index used by global rw ops
}
impl<F: Field> RWLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.gc.clone(),
            self.rw_target.clone(),
            self.rw.clone(),
            self.frame_index.clone(),
            self.address.clone(),
            self.address_ext.clone(),
            self.value.clone(),
            self.sd_index.clone(),
        ]
    }
}

impl<F: Field> RWLookup<F> {
    pub fn stack_push(
        gc: Expression<F>,
        stack_size: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: 0u64.expr(),
            address: stack_size,
            address_ext,
            value,
            sd_index: 0u64.expr(),
        }
    }

    pub fn stack_pop(
        gc: Expression<F>,
        stack_size: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index: 0u64.expr(),
            address: stack_size - 1u64.expr(),
            address_ext,
            value,
            sd_index: 0u64.expr(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_copy(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
        flattened_value_len: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext: address_ext.clone(),
                value: value.clone(),
                sd_index: 0u64.expr(),
            },
            RWLookup {
                gc: gc + flattened_value_len,
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0u64.expr(),
                address: stack_size,
                address_ext,
                value,
                sd_index: 0u64.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_move(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
        flattened_value_len: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: frame_index.clone(),
                address: locals_index.clone(),
                address_ext: address_ext.clone(),
                value: value.clone(),
                sd_index: 0u64.expr(),
            },
            RWLookup {
                gc: gc.clone() + flattened_value_len.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext: address_ext.clone(),
                value: 0u64.expr(),
                sd_index: 0u64.expr(),
            },
            RWLookup {
                gc: gc + flattened_value_len * 2u64.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0u64.expr(),
                address: stack_size,
                address_ext,
                value,
                sd_index: 0u64.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn locals_store(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
        flattened_value_len: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0u64.expr(),
                address: stack_size - 1u64.expr(),
                address_ext: address_ext.clone(),
                value: value.clone(),
                sd_index: 0u64.expr(),
            },
            RWLookup {
                gc: gc + flattened_value_len,
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index,
                address: locals_index,
                address_ext,
                value,
                sd_index: 0u64.expr(),
            },
        )
    }

    pub fn locals_read(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index,
            address: locals_index,
            address_ext,
            value,
            sd_index: 0u64.expr(),
        }
    }

    pub fn locals_write(
        gc: Expression<F>,
        frame_index: Expression<F>,
        locals_index: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Locals as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index,
            address: locals_index,
            address_ext,
            value,
            sd_index: 0u64.expr(),
        }
    }

    pub fn global_write(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
        address_ext: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            frame_index: 0u64.expr(),
            address,
            address_ext,
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
        address_ext: Expression<F>,
        value: Expression<F>,
        flattened_value_len: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0u64.expr(),
                address: global_address.clone(),
                sd_index: sd_index.clone(),
                address_ext: address_ext.clone(),
                value: value.clone(),
            },
            RWLookup {
                gc: gc.clone() + flattened_value_len.clone(),
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0u64.expr(),
                address: global_address,
                sd_index,
                address_ext: address_ext.clone(),
                value: 0u64.expr(),
            },
            RWLookup {
                gc: gc + flattened_value_len * 2u64.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0u64.expr(),
                address: stack_size - 1u64.expr(),
                address_ext,
                value,
                sd_index: 0u64.expr(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn move_to_global(
        gc: Expression<F>,
        stack_size: Expression<F>,
        global_address: Expression<F>,
        sd_index: Expression<F>,
        address_ext: Expression<F>,
        value: Expression<F>,
        flattened_value_len: Expression<F>,
        depth_of_addr_path: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::READ as u64).expr(),
                frame_index: 0u64.expr(),
                address: stack_size - 1u64.expr(),
                address_ext: address_ext.clone(),
                value: value.clone(),
                sd_index: 0u64.expr(),
            },
            RWLookup {
                gc: gc + depth_of_addr_path + flattened_value_len, // + depth_of_addr_path, because, in the middle, a signer reference is popped.
                rw_target: (RWTarget::Global as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                frame_index: 0u64.expr(),
                address: global_address,
                sd_index,
                address_ext,
                value,
            },
        )
    }

    pub fn global_read(
        gc: Expression<F>,
        address: Expression<F>,
        value: Expression<F>,
        sd_index: Expression<F>,
        address_ext: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Global as u64).expr(),
            rw: (RW::READ as u64).expr(),
            frame_index: 0u64.expr(),
            address,
            address_ext,
            value,
            sd_index,
        }
    }
}
