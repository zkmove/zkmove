use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::type_instantiation_table::GenericTypeInstantiation;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct TypeInstantiationTable {
    caller_id: TableColumn,
    caller_module: TableColumn,
    caller_function: TableColumn,
    caller_callin_pc: TableColumn,

    function_instantiation_index: TableColumn,

    instantiation_id: TableColumn,
    instantiation_point_module: TableColumn,
    instantiation_point_function: TableColumn,
    instantiation_point_pc: TableColumn,

    /// if is zero, means no generic
    referred_param_index: TableColumn,
    ty_pos: TableColumn,
    ty_module: TableColumn,
    ty_name: TableColumn,
}

impl TypeInstantiationTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            caller_id: meta.lookup_table_column(),
            caller_module: meta.lookup_table_column(),
            caller_function: meta.lookup_table_column(),
            caller_callin_pc: meta.lookup_table_column(),

            function_instantiation_index: meta.lookup_table_column(),

            instantiation_id: meta.lookup_table_column(),
            instantiation_point_module: meta.lookup_table_column(),
            instantiation_point_function: meta.lookup_table_column(),
            instantiation_point_pc: meta.lookup_table_column(),

            referred_param_index: meta.lookup_table_column(),
            ty_pos: meta.lookup_table_column(),
            ty_module: meta.lookup_table_column(),
            ty_name: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.caller_id,
            self.caller_module,
            self.caller_function,
            self.caller_callin_pc,
            self.function_instantiation_index,
            self.instantiation_id,
            self.instantiation_point_module,
            self.instantiation_point_function,
            self.instantiation_point_pc,
            self.referred_param_index,
            self.ty_pos,
            self.ty_module,
            self.ty_name,
        ]
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        values: Vec<GenericTypeInstantiation>,
    ) -> Result<(), Error> {
        let values = values
            .into_iter()
            .map(|v| {
                vec![
                    F::from_u128(v.caller_id),
                    F::from_u128(v.caller_module as u128),
                    F::from_u128(v.caller_function as u128),
                    F::from_u128(v.caller_callin_pc as u128),
                    F::from_u128(v.instantiation_index as u128),
                    F::from_u128(v.instantiation_id),
                    F::from_u128(v.instantiation_point_module as u128),
                    F::from_u128(v.instantiation_point_function as u128),
                    F::from_u128(v.instantiation_point_pc as u128),
                    F::from_u128(v.referred_ty_idx as u128),
                    F::from_u128(v.ty_pos),
                    F::from_u128(v.ty_module as u128),
                    F::from_u128(v.ty_name as u128),
                ]
            })
            .collect();
        assign_table(
            layouter,
            self.columns(),
            &values,
            "type_instantiations_table",
        )
    }
}

#[derive(Clone, Debug)]
pub struct TypeInstantiationLookup<F: Field> {
    pub caller_id: Expression<F>,
    pub caller_module: Expression<F>,
    pub caller_function: Expression<F>,
    pub caller_callin_pc: Expression<F>,

    pub function_instantiation_index: Expression<F>,
    pub instantiation_id: Expression<F>,
    pub instantiation_point_module: Expression<F>,
    pub instantiation_point_function: Expression<F>,
    pub instantiation_point_pc: Expression<F>,

    pub referred_param_index: Expression<F>,

    pub inst_ty_pos: Expression<F>,
    pub ty_module: Expression<F>,
    pub ty_name: Expression<F>,
}

impl<F: Field> TypeInstantiationLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.caller_id.clone(),
            self.caller_module.clone(),
            self.caller_function.clone(),
            self.caller_callin_pc.clone(),
            self.function_instantiation_index.clone(),
            self.instantiation_id.clone(),
            self.instantiation_point_module.clone(),
            self.instantiation_point_function.clone(),
            self.instantiation_point_pc.clone(),
            self.referred_param_index.clone(),
            self.inst_ty_pos.clone(),
            self.ty_module.clone(),
            self.ty_name.clone(),
        ]
    }
}
