use crate::utils::challenges::Challenges;
use halo2_proofs::circuit::{AssignedCell, Region, Value};
use halo2_proofs::plonk::{Advice, Assigned, Column, ErrorFront as Error, Instance};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use types::Field;

pub struct CachedRegion<'r, 'b, F: Field> {
    region: &'r mut Region<'b, F>,
    advice: Vec<Vec<F>>,
    challenges: &'r Challenges<Value<F>>,
    advice_columns: Vec<Column<Advice>>,
    width_start: usize,
    height_start: usize,
}

impl<'r, 'b, F: Field> CachedRegion<'r, 'b, F> {
    /// New cached region
    pub(crate) fn new(
        region: &'r mut Region<'b, F>,
        challenges: &'r Challenges<Value<F>>,
        advice_columns: Vec<Column<Advice>>,
        height: usize,
        height_start: usize,
    ) -> Self {
        Self {
            region,
            advice: vec![vec![F::ZERO; height]; advice_columns.len()],
            challenges,
            width_start: advice_columns[0].index(),
            height_start,
            advice_columns,
        }
    }

    pub(crate) fn region(&mut self) -> &mut Region<'b, F> {
        self.region
    }

    /// This method replicates the assignment of 1 row at height_start (which
    /// must be already assigned via the CachedRegion) into a range of rows
    /// indicated by offset_begin, offset_end. It can be used as a "quick"
    /// path for assignment for repeated padding rows.
    pub fn replicate_assignment_for_range<A, AR>(
        &mut self,
        annotation: A,
        offset_begin: usize,
        offset_end: usize,
    ) -> Result<(), Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        for (v, column) in self
            .advice
            .iter()
            .map(|values| values[0])
            .zip_eq(self.advice_columns.iter())
        {
            if v.is_zero_vartime() {
                continue;
            }
            let annotation: &String = &annotation().into();
            for offset in offset_begin..offset_end {
                self.region
                    .assign_advice(|| annotation, *column, offset, || Value::known(v))?;
            }
        }

        Ok(())
    }

    /// Assign an advice column value (witness).
    pub fn assign_advice<'v, V, VR, A, AR>(
        &'v mut self,
        annotation: A,
        column: Column<Advice>,
        offset: usize,
        to: V,
    ) -> Result<AssignedCell<VR, F>, Error>
    where
        V: Fn() -> Value<VR> + 'v,
        for<'vr> Assigned<F>: From<&'vr VR>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        // Actually set the value
        let res = self.region.assign_advice(annotation, column, offset, &to);
        // Cache the value
        // Note that the `value_field` in `AssignedCell` might be `Value::unknown` if
        // the column has different phase than current one, so we call to `to`
        // again here to cache the value.
        if res.is_ok() {
            to().map(|f| {
                self.advice[column.index() - self.width_start][offset - self.height_start] =
                    Assigned::from(&f).evaluate();
            });
        }
        res
    }

    pub fn get_fixed(&self, _row_index: usize, _column_index: usize, _rotation: Rotation) -> F {
        unimplemented!("fixed column");
    }

    pub fn get_advice(&self, row_index: usize, column_index: usize, rotation: Rotation) -> F {
        self.advice[column_index - self.width_start]
            [(((row_index - self.height_start) as i32) + rotation.0) as usize]
    }

    pub fn challenges(&self) -> &Challenges<Value<F>> {
        self.challenges
    }

    // TODO: check on these.
    // pub fn keccak_rlc(&self, le_bytes: &[u8]) -> Value<F> {
    //     self.challenges
    //         .keccak_input()
    //         .map(|r| rlc::value(le_bytes, r))
    // }

    // pub fn code_hash(&self, n: U256) -> WordLoHi<Value<F>> {
    //     WordLoHi::from(n).into_value()
    // }

    /// Constrains a cell to have a constant value.
    ///
    /// Returns an error if the cell is in a column where equality has not been
    /// enabled.
    pub fn constrain_constant<VR>(
        &mut self,
        cell: AssignedCell<F, F>,
        constant: VR,
    ) -> Result<(), Error>
    where
        VR: Into<Assigned<F>>,
    {
        self.region.constrain_constant(cell.cell(), constant.into())
    }

    /// Assign an advice column value from instance.
    pub fn assign_advice_from_instance<A, AR>(
        &mut self,
        annotation: A,
        instance: Column<Instance>,
        row: usize,
        column: Column<Advice>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice_from_instance(annotation, instance, row, column, offset)
    }
}
