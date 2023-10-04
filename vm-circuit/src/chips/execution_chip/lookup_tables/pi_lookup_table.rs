use crate::chips::execution_chip::param::word_capacity;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value as CircuitValue};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression};
use movelang::value::Value;
use movelang::value_ext::FlattenedValue;

#[derive(Clone, Debug)]
pub struct PILookupTable {
    pub idx_column: Column<Advice>,
    pub pi_column: Column<Advice>,
}

impl PILookupTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
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

    pub fn assign_table<F: FieldExt>(
        &self,
        layouter: &mut impl Layouter<F>,
        pi: Option<Value<F>>,
        rvr_index_table: Vec<AssignedCell<F, F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let values = match &pi {
            Some(v) => FlattenedValue::from(v).field_values(),
            None => vec![],
        };

        let pi_cells = layouter.assign_region(
            || "pi_table",
            |mut region| {
                for (i, _) in rvr_index_table.iter().enumerate().take(word_capacity() + 1) {
                    let cell = region.assign_advice(
                        || format!("pi_table[{}][0]", i),
                        self.idx_column(),
                        i,
                        || CircuitValue::known(F::from_u128(i as u128)),
                    )?;
                    region.constrain_equal(cell.cell(), rvr_index_table[i].cell())?;
                }

                region.assign_advice(
                    || "pi_table[0][1]",
                    self.pi_column(),
                    0,
                    || CircuitValue::known(F::zero()),
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
pub struct PILookup<F: FieldExt> {
    pub idx: Expression<F>,
    pub pi: Expression<F>,
}

impl<F: FieldExt> PILookup<F> {
    pub fn exprs(&self) -> Vec<Expression<F>> {
        vec![self.idx.clone(), self.pi.clone()]
    }
}
