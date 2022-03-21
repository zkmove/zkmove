use crate::turing_complete::chips::commons::{Expr, StepChipCells};
use crate::turing_complete::chips::lookup::RWLookup;
use halo2::arithmetic::FieldExt;
use halo2::plonk::Expression;
use std::marker::PhantomData;

pub struct BinaryOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BinaryOp<F> {
    pub fn constrain_binary_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 3.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond * gc_expr),
        ]);
    }

    pub fn lookup_binary_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_b.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.value_c.expression.clone(),
            ),
            cond,
        ));
    }
}
