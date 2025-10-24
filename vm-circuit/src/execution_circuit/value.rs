use crate::utils::vm_constraint_builder::VmConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::{Cell, CellManager, CellManagerColumns, CellType};
use circuit_tool::cell_placement_strategy::CMFixedHeightStrategy;
use circuit_tool::challenges::Challenges;
use circuit_tool::rlc;
use circuit_tool::word::WordLoHiCell;
use field_exts::Field;
use halo2_proofs::circuit::{AssignedCell, Value as Halo2Value};
use halo2_proofs::plonk::{ConstraintSystem, ErrorFront as Error, Expression};
use types::integer::Integer;
use util::pow_of_two_expr;
use util::Expr;

pub const NUM_OF_BYTES_U8: usize = 1;
pub const NUM_OF_BYTES_U16: usize = 2;
pub const NUM_OF_BYTES_U32: usize = 4;
pub const NUM_OF_BYTES_U64: usize = 8;
pub const NUM_OF_BYTES_U128: usize = 16;
pub const NUM_OF_BYTES_U256: usize = 32;
pub const NUM_OF_NIBBLE_U256: usize = NUM_OF_BYTES_U256 * 2;

pub const INTEGER_NUM_OF_BYTES_SET: [usize; 6] = [
    NUM_OF_BYTES_U8,
    NUM_OF_BYTES_U16,
    NUM_OF_BYTES_U32,
    NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U128,
    NUM_OF_BYTES_U256,
];

#[derive(Clone, Debug)]
pub(crate) struct Value<F, const N: usize> {
    cells: [Cell<F>; N],
    challenge: Expression<F>,
}

impl<F: Field, const N: usize> Value<F, N> {
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(value.len(), N);
        let mut assigned = vec![];
        for (cell, v) in self.cells.iter().zip(value) {
            assigned.push(cell.assign(region, offset, Halo2Value::known(v))?);
        }
        Ok(assigned)
    }
}

impl<F: Field, const N: usize> Value<F, N> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &mut CellManagerColumns,
        cell_manager: &mut CellManager<CMFixedHeightStrategy>,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let cells = cell_manager
            .query_cells(meta, cell_manager_columns, CellType::StoragePhase1, N)
            .try_into()
            .unwrap();
        Value {
            cells,
            challenge: challenges.row_keccak_input(),
        }
    }
    pub(crate) fn cells(&self) -> &[Cell<F>; N] {
        &self.cells
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
pub(crate) struct WordU16<F>(WordLoHiCell<F>);

impl<F: Field> WordU16<F> {
    pub(crate) fn construct(cb: &mut VmConstraintBuilder<F>) -> Self {
        Self(WordLoHiCell::new([cb.query_byte(), cb.query_byte()]))
    }
    pub(crate) fn new(cells: [Cell<F>; 2]) -> Self {
        Self(WordLoHiCell::new(cells))
    }
    pub(crate) fn cells(&self) -> [Cell<F>; 2] {
        [self.0.lo(), self.0.hi()]
    }
    pub(crate) fn lo(&self) -> Cell<F> {
        self.0.lo()
    }
    pub(crate) fn hi(&self) -> Cell<F> {
        self.0.hi()
    }
    pub(crate) fn expr(&self) -> Expression<F> {
        self.lo().expr() + self.hi().expr() * pow_of_two_expr(8)
    }
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: u16,
    ) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        self.0
            .lo()
            .assign(region, offset, Halo2Value::known(F::from(bytes[0] as u64)))?;
        self.0
            .hi()
            .assign(region, offset, Halo2Value::known(F::from(bytes[1] as u64)))?;
        Ok(())
    }
    pub(crate) fn assign_with_fe(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lo: F,
        hi: F,
    ) -> Result<(), Error> {
        self.0.lo().assign(region, offset, Halo2Value::known(lo))?;
        self.0.hi().assign(region, offset, Halo2Value::known(hi))?;
        Ok(())
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
