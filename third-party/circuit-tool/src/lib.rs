#![allow(dead_code)]

pub mod base_constraint_builder;
pub mod cached_region;
pub mod cell_manager;
pub mod cell_placement_strategy;
pub mod challenges;
pub mod rlc;
pub mod stored_expression;
pub mod word;

use field_exts::Field;
use halo2_proofs::plonk::{ConstraintSystem, VirtualCells};
use util::Expr;

/// Steal the expression from gate
pub fn query_expression<F: Field, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0u64.expr())
    });
    expr.unwrap()
}
