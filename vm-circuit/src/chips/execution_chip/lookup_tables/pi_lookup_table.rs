use crate::chips::execution_chip::param::word_capacity;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value as CircuitValue};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression};
use movelang::value::Value;
use movelang::value_ext::FlattenedValue;
use types::Field;

pub struct PIFieldValues<F: Field>(pub Vec<F>);

impl<F: Field> From<&Value> for PIFieldValues<F> {
    fn from(v: &Value) -> Self {
        let mut field_values = FlattenedValue::from(v).field_values();

        // fill up with 0
        while field_values.len() < word_capacity() * 2 {
            field_values.push(F::ZERO);
        }
        Self(field_values)
    }
}

#[derive(Clone, Debug)]
pub struct PILookupTable {
    pub idx_column: Column<Advice>,
    pub pi_column: Column<Advice>,
}

impl PILookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let idx_column = meta.advice_column();
        let pi_column = meta.advice_column();
        meta.enable_equality(idx_column);
        meta.enable_equality(pi_column);

        PILookupTable {
            idx_column,
            pi_column,
        }
    }

    pub fn columns(&self) -> Vec<Column<Advice>> {
        vec![self.idx_column, self.pi_column]
    }

    pub fn pi_column(&self) -> Column<Advice> {
        self.pi_column
    }

    pub fn idx_column(&self) -> Column<Advice> {
        self.idx_column
    }

    pub fn num_of_rows() -> usize {
        word_capacity() * 2 + 1
    }

    // NOTICE: table height must be consistent with assign_table()
    pub fn table_height(&self) -> usize {
        Self::num_of_rows()
    }

    pub fn assign_table<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        pi: Option<Value>,
        pi_index_table: Vec<AssignedCell<F, F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let values = match &pi {
            Some(v) => PIFieldValues::from(v).0,
            None => vec![],
        };

        let pi_cells = layouter.assign_region(
            || "pi_table",
            |mut region| {
                for (i, index_cell) in pi_index_table.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("pi_table[{}][0]", i),
                        self.idx_column(),
                        i,
                        || CircuitValue::known(F::from_u128(i as u128)),
                    )?;
                    region.constrain_equal(cell.cell(), index_cell.cell())?;
                }

                region.assign_advice(
                    || "pi_table[0][1]",
                    self.pi_column(),
                    0,
                    || CircuitValue::known(F::ZERO),
                )?;
                let mut cells = Vec::new();
                for (idx, value) in values.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("pi_table[{}][1]", idx + 1),
                        self.pi_column(),
                        idx + 1,
                        || CircuitValue::known(*value),
                    )?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )?;
        Ok(pi_cells)
    }
}

#[derive(Clone, Debug)]
pub struct PILookup<F: Field> {
    pub idx: Expression<F>,
    pub pi: Expression<F>,
}

impl<F: Field> PILookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![self.idx.clone(), self.pi.clone()]
    }
}
