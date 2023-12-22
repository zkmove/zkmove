use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::function_calls::FunctionCall;
use halo2_base::halo2_proofs::circuit::Layouter;
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::plonk::{Error, Expression, TableColumn};
use types::Field;

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
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
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

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        calls: Vec<FunctionCall>,
    ) -> Result<(), Error> {
        let values = calls
            .into_iter()
            .map(|func_call| {
                vec![
                    F::from_u128(func_call.type_ as u128),
                    F::from_u128(func_call.module_index as u128),
                    F::from_u128(func_call.function_index as u128),
                    F::from_u128(func_call.pc as u128),
                    F::from_u128(func_call.next_module_index as u128),
                    F::from_u128(func_call.next_function_index as u128),
                    F::from_u128(func_call.next_pc as u128),
                ]
            })
            .collect();
        assign_table(layouter, self.columns(), &values, "func_call_table")
    }

    pub fn table_height(&self, calls: &Vec<FunctionCall>) -> usize {
        calls.len() + 1
    }
}

#[derive(Clone, Debug)]
pub struct CallLookup<F: Field> {
    pub type_: Expression<F>,
    pub module_index: Expression<F>,
    pub function_index: Expression<F>,
    pub pc: Expression<F>,
    pub next_module_index: Expression<F>,
    pub next_function_index: Expression<F>,
    pub next_pc: Expression<F>,
}

impl<F: Field> CallLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.type_.clone(),
            self.module_index.clone(),
            self.function_index.clone(),
            self.pc.clone(),
            self.next_module_index.clone(),
            self.next_function_index.clone(),
            self.next_pc.clone(),
        ]
    }
}
