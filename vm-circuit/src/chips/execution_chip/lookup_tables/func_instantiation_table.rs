use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::func_instantiation_table::FuncInstantiation;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};

#[derive(Clone, Debug)]
pub struct FuncInstantiationTable {
    //caller_module_addr: TableColumn,
    caller_module: TableColumn,
    caller_function: TableColumn,

    function_instantiation_index: TableColumn,
    instantiated_module: TableColumn,
    instantiated_function: TableColumn,
    instantiation_point_pc: TableColumn,
    inst_ty_pos: TableColumn,
    /// if is zero, means no generic
    refered_param_index: TableColumn,

    ty_module: TableColumn,
    ty_name: TableColumn,
}

impl FuncInstantiationTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            caller_module: meta.lookup_table_column(),
            caller_function: meta.lookup_table_column(),

            function_instantiation_index: meta.lookup_table_column(),
            instantiated_module: meta.lookup_table_column(),
            instantiated_function: meta.lookup_table_column(),
            instantiation_point_pc: meta.lookup_table_column(),

            inst_ty_pos: meta.lookup_table_column(),
            refered_param_index: meta.lookup_table_column(),
            ty_module: meta.lookup_table_column(),
            ty_name: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.caller_module,
            self.caller_function,
            self.function_instantiation_index,
            self.instantiated_module,
            self.instantiated_function,
            self.instantiation_point_pc,
            self.inst_ty_pos,
            self.refered_param_index,
            self.ty_module,
            self.ty_name,
        ]
    }

    pub fn assign_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        values: Vec<FuncInstantiation>,
    ) -> Result<(), Error> {
        let values = values
            .into_iter()
            .map(|v| {
                vec![
                    F::from_u128(v.caller_module as u128),
                    F::from_u128(v.caller_function as u128),
                    F::from_u128(v.instantiation_index as u128),
                    F::from_u128(v.instantiated_module as u128),
                    F::from_u128(v.instantiated_function as u128),
                    F::from_u128(v.instantiation_point_pc as u128),
                    F::from_u128(v.ty_pos),
                    F::from_u128(v.refered_ty_idx as u128),
                    F::from_u128(v.ty_module as u128),
                    F::from_u128(v.ty_name as u128),
                ]
            })
            .collect();
        assign_table(
            layouter,
            self.columns(),
            &values,
            "func_instantiations_table",
        )
    }
}

pub struct FuncInstantiationLookup<F: FieldExt> {
    pub caller_module: Expression<F>,
    pub caller_function: Expression<F>,
    pub function_instantiation_index: Expression<F>,
    pub instantiated_module: Expression<F>,
    pub instantiated_function: Expression<F>,
    pub instantiation_point_pc: Expression<F>,
    pub inst_ty_pos: Expression<F>,
    pub refered_param_index: Expression<F>,
    pub ty_module: Expression<F>,
    pub ty_name: Expression<F>,
}

impl<F: FieldExt> FuncInstantiationLookup<F> {
    pub fn expressions(&self) -> Vec<Expression<F>> {
        vec![
            self.caller_module.clone(),
            self.caller_function.clone(),
            self.function_instantiation_index.clone(),
            self.instantiated_module.clone(),
            self.instantiated_function.clone(),
            self.instantiation_point_pc.clone(),
            self.inst_ty_pos.clone(),
            self.refered_param_index.clone(),
            self.ty_module.clone(),
            self.ty_name.clone(),
        ]
    }
}
