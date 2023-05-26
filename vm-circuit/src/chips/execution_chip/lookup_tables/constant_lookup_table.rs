use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::const_table::ConstantInfo;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};
use movelang::value::PrimitiveValue;

#[derive(Clone, Debug)]
pub struct ConstantLookupTable {
    pub module_index: TableColumn,
    pub constant_index: TableColumn,
    pub value: TableColumn,
}
//pub const BYTECODE_LOOKUP_TABLE_WIDTH: usize = 3;

impl ConstantLookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        ConstantLookupTable {
            module_index: meta.lookup_table_column(),
            constant_index: meta.lookup_table_column(),
            value: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![self.module_index, self.constant_index, self.value]
    }

    pub fn assign_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        traces: Vec<ConstantInfo>,
    ) -> Result<(), Error> {
        let values = traces
            .into_iter()
            .map(|t| {
                let v: PrimitiveValue<F> = t.value.into();
                vec![
                    F::from_u128(t.module_index as u128),
                    F::from_u128(t.constant_index as u128),
                    v.value().unwrap(),
                ]
            })
            .collect();
        assign_table(layouter, self.columns(), &values, "constant_table")
    }
}

#[derive(Clone, Debug)]
pub struct ConstantLookup<F: FieldExt> {
    pub module_index: Expression<F>,
    pub constant_index: Expression<F>,
    pub value: Expression<F>,
}

impl<F: FieldExt> ConstantLookup<F> {
    pub fn expressions(&self) -> Vec<Expression<F>> {
        vec![
            self.module_index.clone(),
            self.constant_index.clone(),
            self.value.clone(),
        ]
    }
}
