// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};

pub mod _mod;
pub mod abort;
pub mod add;
pub mod and;
pub mod br_false;
pub mod br_true;
pub mod branch;
pub mod call;
pub mod common;
pub mod copy_loc;
pub mod div;
pub mod eq;
pub mod ld_false;
pub mod ld_true;
pub mod ldu128;
pub mod ldu64;
pub mod ldu8;
pub mod lt;
pub mod move_loc;
pub mod mul;
pub mod neq;
pub mod not;
pub mod or;
pub mod pop;
pub mod ret;
pub mod st_loc;
pub mod sub;

pub trait Instructions<F: FieldExt> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    );

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error>;
}
