// Copyright (c) zkMove Authors

use crate::turing_complete::chips::commons::Expr;
use crate::turing_complete::circuit_inputs::RW;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWTarget {
    Stack = 0,
    Locals,
}

pub struct RWLookup<F: FieldExt> {
    pub gc: Expression<F>,         // global counter
    pub rw_target: Expression<F>,  // RWTarget
    pub rw: Expression<F>,         // read or write
    pub call_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,    // locals index, or stack address
    pub value: Expression<F>,
}

impl<F: FieldExt> RWLookup<F> {
    pub fn stack_push(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            call_index: 0.expr(),
            address: stack_size,
            value,
        }
    }

    pub fn stack_pop(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::READ as u64).expr(),
            call_index: 0.expr(),
            address: stack_size,
            value,
        }
    }
}
