use crate::chips::execution_chip::lookup_tables::utils::assign_table;
use crate::witness::call_trace_table::CallTrace;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, TableColumn};
use types::Field;

#[derive(Clone, Debug)]
pub struct CallTraceTable {
    caller_id: TableColumn,
    caller_module: TableColumn,
    caller_function: TableColumn,
    caller_callin_pc: TableColumn,

    callee_id: TableColumn,
    callee_module: TableColumn,
    callee_function: TableColumn,
    callee_callin_pc: TableColumn,
}

impl CallTraceTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            caller_id: meta.lookup_table_column(),
            caller_module: meta.lookup_table_column(),
            caller_function: meta.lookup_table_column(),
            caller_callin_pc: meta.lookup_table_column(),
            callee_id: meta.lookup_table_column(),
            callee_module: meta.lookup_table_column(),
            callee_function: meta.lookup_table_column(),
            callee_callin_pc: meta.lookup_table_column(),
        }
    }

    pub fn columns(&self) -> Vec<TableColumn> {
        vec![
            self.caller_id,
            self.caller_module,
            self.caller_function,
            self.caller_callin_pc,
            self.callee_id,
            self.callee_module,
            self.callee_function,
            self.callee_callin_pc,
        ]
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        traces: Vec<CallTrace>,
    ) -> Result<(), Error> {
        let values = traces
            .into_iter()
            .map(|t| {
                vec![
                    F::from_u128(t.caller_id),
                    F::from_u128(t.caller_module as u128),
                    F::from_u128(t.caller_function as u128),
                    F::from_u128(t.caller_callin_pc as u128),
                    F::from_u128(t.callee_id),
                    F::from_u128(t.callee_module as u128),
                    F::from_u128(t.callee_function as u128),
                    F::from_u128(t.callee_callin_pc as u128),
                ]
            })
            .collect();
        assign_table(layouter, self.columns(), &values, "call_trace_table")
    }
}

#[derive(Clone, Debug)]
pub struct CallTraceLookup<F: Field> {
    pub caller_id: Expression<F>,
    pub caller_module: Expression<F>,
    pub caller_function: Expression<F>,
    pub caller_callin_pc: Expression<F>,

    pub callee_id: Expression<F>,
    pub callee_module: Expression<F>,
    pub callee_function: Expression<F>,
    pub callee_callin_pc: Expression<F>,
}

impl<F: Field> CallTraceLookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![
            self.caller_id.clone(),
            self.caller_module.clone(),
            self.caller_function.clone(),
            self.caller_callin_pc.clone(),
            self.callee_id.clone(),
            self.callee_module.clone(),
            self.callee_function.clone(),
            self.callee_callin_pc.clone(),
        ]
    }
}
