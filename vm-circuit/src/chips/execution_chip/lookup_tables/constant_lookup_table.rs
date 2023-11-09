use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::const_table::ConstantInfo;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};
use movelang::value::AddressPath;
use movelang::value_ext::FlattenedValue;
use types::Field;

#[derive(Clone, Debug)]
pub struct ConstantLookupTable {
    pub module_index: TableColumn,
    pub constant_index: TableColumn,
    pub addr_ext: TableColumn,
    pub value: TableColumn,
}
//pub const CONSTANT_LOOKUP_TABLE_WIDTH: usize = 4;

impl ConstantLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        ConstantLookupTable {
            module_index: meta.lookup_table_column(),
            constant_index: meta.lookup_table_column(),
            addr_ext: meta.lookup_table_column(),
            value: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.module_index,
            self.constant_index,
            self.addr_ext,
            self.value,
        ]
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        traces: Vec<ConstantInfo>,
    ) -> Result<(), Error> {
        let values = traces
            .into_iter()
            .flat_map(|t| {
                let module_idx = F::from_u128(t.module_index as u128);
                let constant_idx = F::from_u128(t.constant_index as u128);
                let flattened_value = FlattenedValue::from(&t.value.into());
                flattened_value.0.into_iter().map(move |(indexes, val)| {
                    vec![
                        module_idx,
                        constant_idx,
                        F::from_u128(AddressPath::<F>::from(indexes).fold()),
                        val.value().unwrap(),
                    ]
                })
            })
            .collect::<Vec<_>>();
        assign_table(layouter, self.columns(), &values, "constant_table")
    }
}

#[derive(Clone, Debug)]
pub struct ConstantLookup<F: Field> {
    pub module_index: Expression<F>,
    pub constant_index: Expression<F>,
    pub addr_ext: Expression<F>,
    pub value: Expression<F>,
}

impl<F: Field> ConstantLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.module_index.clone(),
            self.constant_index.clone(),
            self.addr_ext.clone(),
            self.value.clone(),
        ]
    }
}
