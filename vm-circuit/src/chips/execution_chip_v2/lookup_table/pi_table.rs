use crate::chips::execution_chip_v2::lookup_table::utils::assign_fixed_table;
use crate::table::LookupTable;
use aptos_move_witnesses::static_info::StaticInfo;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem, Error, Fixed};
use types::Field;

#[derive(Clone, Copy, Debug)]
pub struct PublicInputsLookupTable {
    pub arg_index: Column<Fixed>,
    pub is_pi: Column<Fixed>,
}

impl PublicInputsLookupTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        PublicInputsLookupTable {
            arg_index: meta.fixed_column(),
            is_pi: meta.fixed_column(),
        }
    }

    pub fn columns(&self) -> Vec<Column<Fixed>> {
        vec![self.arg_index, self.is_pi]
    }

    pub fn build<F: Field>(&self, static_info: &StaticInfo) -> Vec<Vec<F>> {
        let num_arg = static_info
            .get_entry_function(
                static_info.entry.module_index,
                static_info.entry.function_index,
            )
            .expect("cannot find function")
            .num_arg as usize;

        // Create rows for all argument indices (0 to num_arg - 1)
        let mut rows = Vec::new();
        for i in 0..num_arg {
            let is_public_input = static_info.public_inputs.contains(&i);
            rows.push(vec![
                F::from(i as u64),               // arg_index
                F::from(is_public_input as u64), // is_pi (1 if public input, 0 otherwise)
            ]);
        }
        rows
    }

    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        assign_fixed_table(
            layouter,
            self.columns(),
            &self.build(static_info),
            "public_inputs_table",
        )
    }
}

impl<F: Field> LookupTable<F> for PublicInputsLookupTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.columns().into_iter().map(|c| c.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec!["arg_index".to_string(), "is_pi".to_string()]
    }
}
