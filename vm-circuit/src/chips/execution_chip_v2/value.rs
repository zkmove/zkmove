use crate::chips::execution_chip::utils::constraint_builder_v2::ConstraintBuilderV2;
use crate::chips::utilities::Expr;
use crate::utils::cell_manager::{Cell, CellManager, CellType};
use crate::utils::cell_placement_strategy::CMFixedWidthStrategy;
use crate::utils::challenges::Challenges;
use crate::utils::rlc::rlc;
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use types::Field;

#[derive(Clone, Debug)]
pub(crate) struct Value<F, const N: usize> {
    cells: [Cell<F>; N],
    challenge: Expression<F>,
}

impl<F: Field, const N: usize> Value<F, N> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager: &mut CellManager<CMFixedWidthStrategy>,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let cells = cell_manager
            .query_cells(meta, CellType::StoragePhase1, N)
            .try_into()
            .unwrap();
        Value {
            cells,
            challenge: challenges.keccak_input(),
        }
    }
    pub(crate) fn expr(&self) -> Expression<F> {
        rlc::expr(&self.exprs(), self.challenge.clone())
    }
    pub(crate) fn exprs(&self) -> [Expression<F>; N] {
        self.cells.clone().map(|c| c.expr())
    }
    pub(crate) fn as_integer(&self) -> Integer<F> {
        match N {
            2 => Integer {
                lo: self.cells[0].expr(),
                hi: self.cells[1].expr(),
            },
            _ => unimplemented!(),
        }
    }
    pub(crate) fn as_bool(&self) -> Bool<F> {
        match N {
            2 => Bool(self.cells[0].expr()),
            _ => unimplemented!(),
        }
    }
    pub(crate) fn as_header(&self) -> ValueHeader<F> {
        match N {
            2 => ValueHeader {
                flen: self.cells[0].expr(),
                len: self.cells[1].expr(),
            },
            _ => unimplemented!(),
        }
    }
    pub(crate) fn as_reference(&self) -> Reference<F> {
        match N {
            2 => Reference {
                index: self.cells[0].expr(),
                sub_index: self.cells[1].expr(),
            },
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Integer<F> {
    lo: Expression<F>,
    hi: Expression<F>,
}

impl<F: Field> Integer<F> {
    pub(crate) fn new(lo: Expression<F>, hi: Expression<F>) -> Self {
        Self { lo, hi }
    }
    pub(crate) fn lo(&self) -> Expression<F> {
        self.lo.clone()
    }
    pub(crate) fn hi(&self) -> Expression<F> {
        self.hi.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Bool<F>(Expression<F>);

impl<F: Field> Bool<F> {
    pub(crate) fn new(value: Expression<F>) -> Self {
        Self(value)
    }
    pub(crate) fn expr(&self) -> Expression<F> {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ValueHeader<F> {
    flen: Expression<F>,
    len: Expression<F>,
}

impl<F: Field> ValueHeader<F> {
    pub(crate) fn flen(&self) -> Expression<F> {
        self.flen.clone()
    }
    pub(crate) fn len(&self) -> Expression<F> {
        self.len.clone()
    }
    pub(crate) fn pair(len: Expression<F>, flen: Expression<F>) -> Self {
        Self { flen, len }
    }
}

pub(crate) struct Index<F> {
    frame_index: Expression<F>,
    local_index: Expression<F>,
}
impl<F: Field> Index<F> {
    pub(crate) fn new(frame_index: Expression<F>, local_index: Expression<F>) -> Self {
        Self {
            frame_index,
            local_index,
        }
    }
    pub(crate) fn expr(&self) -> Expression<F> {
        self.frame_index.clone() + self.local_index.clone() * 2u64.pow(16).expr()
    }
}
pub(crate) struct Reference<F> {
    index: Expression<F>,
    sub_index: Expression<F>,
}

impl<F: Field> Reference<F> {
    pub(crate) fn index(&self) -> Expression<F> {
        self.index.clone()
    }
    pub(crate) fn sub_index(&self) -> Expression<F> {
        self.sub_index.clone()
    }
}
