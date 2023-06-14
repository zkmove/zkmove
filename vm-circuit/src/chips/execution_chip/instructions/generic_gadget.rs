// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::call_trace_table::CallTraceLookup;
use crate::chips::execution_chip::lookup_tables::input_type_element_table::InputTypeElementLookup;
use crate::chips::execution_chip::lookup_tables::type_instantiation_table::TypeInstantiationLookup;

use crate::chips::execution_chip::param::GENERIC_TYPE_CAPACITY;
use crate::chips::execution_chip::step_chip::StepChipCells;

use crate::chips::execution_chip::utils::constraint_builder::ConstraintBuilder;
use crate::chips::math_gadget::is_zero::IsZeroGadget;
use crate::chips::utilities::{Cell, Expr};
use crate::witness::execution_steps::{GenericTypeData, MaterializedTypeInfo};
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use logger::error;

#[derive(Clone, Debug)]
pub(crate) struct GenericTypeCells<F> {
    pub(crate) inst_ty_pos: Cell<F>,
    pub(crate) inst_ty_pos_max: Cell<F>,
    pub(crate) inst_ty_pos_max_inverse: Cell<F>,
    pub(crate) referred_param_index: Cell<F>,
    pub(crate) referred_param_index_is_zero: IsZeroGadget<F>,
    pub(crate) ty_arg_pos: Cell<F>,
    pub(crate) ty_arg_module: Cell<F>,
    pub(crate) ty_arg_name: Cell<F>,
    pub(crate) ty_mask: Cell<F>,
}

impl<F: FieldExt> GenericTypeCells<F> {
    fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let inst_ty_pos = cb.alloc_cell();
        let inst_ty_pos_max = cb.alloc_cell();
        let inst_ty_pos_max_inverse = cb.alloc_cell();
        let referred_param_index = cb.alloc_cell();
        let referred_param_index_is_zero = IsZeroGadget::construct(cb, referred_param_index.expr());
        let ty_arg_pos = cb.alloc_cell();
        let ty_arg_module = cb.alloc_cell();
        let ty_arg_name = cb.alloc_cell();
        let ty_mask = cb.alloc_cell();

        GenericTypeCells {
            inst_ty_pos,
            inst_ty_pos_max,
            inst_ty_pos_max_inverse,
            referred_param_index,
            referred_param_index_is_zero,
            ty_arg_pos,
            ty_arg_module,
            ty_arg_name,
            ty_mask,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct GenericTypeGadget<F> {
    #[allow(dead_code)]
    pub(crate) name: &'static str,
    pub(crate) type_cells: Vec<GenericTypeCells<F>>,

    caller_callin_pc: Expression<F>,
    callee_id: Expression<F>,
    callee_module: Expression<F>,
    callee_function: Expression<F>,
    instantiation_index: Expression<F>,
}

impl<F: FieldExt> GenericTypeGadget<F> {
    pub(crate) fn construct(
        name: &'static str,
        cb: &mut ConstraintBuilder<F>,
        caller_callin_pc: Expression<F>,
        callee_id: Expression<F>,
        callee_module: Expression<F>,
        callee_function: Expression<F>,
        instantiation_index: Expression<F>,
    ) -> Self {
        let cells = (1..=GENERIC_TYPE_CAPACITY)
            .map(|_i| GenericTypeCells::construct(cb))
            .collect();
        Self {
            type_cells: cells,
            name,
            caller_callin_pc,
            callee_id,
            callee_module,
            callee_function,
            instantiation_index,
        }
    }
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        data: GenericTypeData,
    ) -> Result<(), Error> {
        if data.generic_types.len() > GENERIC_TYPE_CAPACITY {
            error!("generic types to large");
            return Err(Error::Synthesis);
        }

        for (i, item) in data
            .generic_types
            .iter()
            .chain(&vec![
                MaterializedTypeInfo::default();
                GENERIC_TYPE_CAPACITY - data.generic_types.len()
            ])
            .enumerate()
        {
            let cells = &self.type_cells[i];
            let inst_ty_pos = &cells.inst_ty_pos;
            let inst_ty_pos_max = &cells.inst_ty_pos_max;
            let inst_ty_pos_max_inverse = &cells.inst_ty_pos_max_inverse;
            let referred_param_index = &cells.referred_param_index;
            let referred_param_index_is_zero = &cells.referred_param_index_is_zero;

            let ty_arg_pos = &cells.ty_arg_pos;
            let ty_arg_module = &cells.ty_arg_module;
            let ty_arg_name = &cells.ty_arg_name;
            let ty_mask = &cells.ty_mask;

            let mask_value = if i < data.generic_types.len() {
                F::ZERO
            } else {
                F::ONE
            };
            ty_mask.assign(region, offset, Some(mask_value))?;

            inst_ty_pos.assign(region, offset, Some(F::from_u128(item.inst_ty_pos)))?;
            let pos_max = F::from_u128(item.inst_ty_pos_max);
            inst_ty_pos_max.assign(region, offset, Some(pos_max))?;
            inst_ty_pos_max_inverse.assign(
                region,
                offset,
                Some(pos_max.invert().unwrap_or(F::ZERO)),
            )?;
            referred_param_index.assign(
                region,
                offset,
                Some(F::from_u128(item.referred_param_index as u128)),
            )?;
            referred_param_index_is_zero.assign(
                region,
                offset,
                F::from_u128(item.referred_param_index as u128),
            )?;

            ty_arg_pos.assign(region, offset, Some(F::from_u128(item.ty_arg_pos)))?;
            ty_arg_module.assign(
                region,
                offset,
                Some(F::from_u128(item.ty_arg_module as u128)),
            )?;
            ty_arg_name.assign(region, offset, Some(F::from_u128(item.ty_arg_name as u128)))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn configure(&self, _cells: &StepChipCells<F>, cb: &mut ConstraintBuilder<F>) {
        let caller_id = cb.curr.cells.context_id.clone();
        let caller_module = cb.curr.cells.module_index.clone();
        let caller_function = cb.curr.cells.function_index.clone();
        let caller_callin_pc = self.caller_callin_pc.clone();

        let callee_callin_pc = cb.curr.cells.pc.clone();
        let callee_id = self.callee_id.clone();
        let callee_module = self.callee_module.clone();
        let callee_function = self.callee_function.clone();
        let instantiation_index = self.instantiation_index.clone();
        // TODO: In function call, we constraint: caller_id/callee_id in call trace table.
        // in other opcode, we constraint: step_cur.cells.context_id == step_nexr.cells.context_id
        let lookup_calltrace = CallTraceLookup {
            caller_id: caller_id.expression.clone(),
            caller_module: caller_module.expression.clone(),
            caller_function: caller_function.expression.clone(),
            caller_callin_pc: caller_callin_pc.clone(),
            callee_id: callee_id.clone(),
            callee_module: callee_module.clone(),
            callee_function: callee_function.clone(),
            callee_callin_pc: callee_callin_pc.expression.clone(),
        };

        cb.add_lookup(
            Box::leak(format!("{}(call_trace)", self.name).into_boxed_str()),
            lookup_calltrace,
        );

        for (_i, cells) in self.type_cells.iter().enumerate() {
            let inst_ty_pos = &cells.inst_ty_pos;
            let inst_ty_pos_max = &cells.inst_ty_pos_max;
            let inst_ty_pos_max_inverse = &cells.inst_ty_pos_max_inverse;
            let referred_param_index = &cells.referred_param_index;
            let referred_param_index_is_zero = &cells.referred_param_index_is_zero;

            let ty_arg_pos = &cells.ty_arg_pos;
            let ty_arg_module = &cells.ty_arg_module;
            let ty_arg_name = &cells.ty_arg_name;
            let ty_mask = &cells.ty_mask;

            cb.condition(1.expr() - ty_mask.expr(), |cb| {
                // FIXME: require inst_ty_pos_max is pow2 of [4,8,..,128]
                cb.add_constraint(
                    "inst_ty_pos_max*inst_ty_pos_max_inverse = 1",
                    1.expr() - inst_ty_pos_max_inverse.expr() * inst_ty_pos_max.expr(),
                );
                cb.add_constraints(cells.referred_param_index_is_zero.configure());

                // TODO: inst_ty_pos < inst_ty_pos_max && inst_ty_pos > inst_ty_pos_max / 16
                let is_not_generic = referred_param_index_is_zero.expr();

                // if the type element is not generic, then it must be in func-instantiation static table.
                // or else, it must be referring an input type.

                cb.condition(is_not_generic.clone(), |cb| {
                    cb.add_constraint(
                        "inst_ty_pos == real_ty_pos when not generic",
                        inst_ty_pos.expr() - ty_arg_pos.expr(),
                    );
                    let lookup_func_instantiation_type = TypeInstantiationLookup {
                        caller_id: caller_id.expr(),
                        caller_module: caller_module.expr(),
                        caller_function: caller_function.expr(),
                        caller_callin_pc: caller_callin_pc.clone(),

                        function_instantiation_index: instantiation_index.clone(),

                        instantiation_id: callee_id.clone(),
                        instantiation_point_module: callee_module.clone(),
                        instantiation_point_function: callee_function.clone(),
                        instantiation_point_pc: callee_callin_pc.expr(),

                        referred_param_index: 0.expr(),
                        inst_ty_pos: inst_ty_pos.expr(),
                        ty_module: ty_arg_module.expr(),
                        ty_name: ty_arg_name.expr(),
                    };
                    cb.add_lookup(
                        Box::leak(
                            format!("{}(type_instantiation - no-generic)", self.name)
                                .into_boxed_str(),
                        ),
                        lookup_func_instantiation_type,
                    );
                });

                // generic

                cb.condition(1.expr() - is_not_generic, |cb| {
                    let caller_type_arg_lookup = InputTypeElementLookup {
                        ty_arg_pos: (ty_arg_pos.expr() - inst_ty_pos.expr())
                            * inst_ty_pos_max_inverse.expr()
                            * 16.expr()
                            + referred_param_index.expr(), // le encoding of ty_arg pos

                        ty_arg_module: ty_arg_module.expr(),
                        ty_arg_name: ty_arg_name.expr(),
                    };

                    cb.add_lookup(
                        Box::leak(format!("{}(input_type)", self.name).into_boxed_str()),
                        caller_type_arg_lookup,
                    );
                });
            });
        }
    }
}
