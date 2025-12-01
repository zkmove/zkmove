use crate::sub_index::SubIndex;
use crate::to_scalars::ToScalars;
use crate::value_header::ValueHeader;
use crate::word_generic::{WordLoHi, WordLoHiCell};
use circuit_tool::base_constraint_builder::ConstraintBuilder;
use circuit_tool::cached_region::CachedRegion;
use circuit_tool::cell_manager::{Cell, CellManager, CellManagerColumns, CellType};
use circuit_tool::cell_placement_strategy::CMFixedHeightStrategy;
use circuit_tool::challenges::Challenges;
use circuit_tool::rlc;
use field_exts::util::{pow_of_two, pow_of_two_expr, Expr, Scalar};
use field_exts::Field;
use halo2_proofs::circuit::{AssignedCell, Value};
use halo2_proofs::plonk::{ConstraintSystem, ErrorFront as Error, Expression};
use move_core_types::account_address::AccountAddress;
use move_vm_runtime::witnessing::traced_value;
use move_vm_runtime::witnessing::traced_value::SimpleValue;
use table_type::Table;

/// A VM word encoded as two 128‑bit limbs: `lo` (lower 128 bits) and `hi` (upper 128 bits), in little‑endian form.
/// VM circuit path: `SimpleValue` → `Word` → `CircuitWord<F>` or scalars → assigned to `WordCells<F>`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Word(WordLoHi<u128>);

impl Word {
    pub fn new(limbs: [u128; 2]) -> Self {
        Word(WordLoHi::new(limbs))
    }
    pub fn lo(&self) -> u128 {
        self.0.lo()
    }
    pub fn hi(&self) -> u128 {
        self.0.hi()
    }
}

impl From<bool> for Word {
    fn from(b: bool) -> Self {
        Word::new([b as u128, 0u128])
    }
}

impl From<&traced_value::Reference> for Word {
    fn from(r: &traced_value::Reference) -> Self {
        let frame_index = r.frame_index as u128;
        let local_index = r.local_index as u128;
        assert!(frame_index < (1u128 << 10), "frame_index out of 2^10 range");
        assert!(local_index < (1u128 << 10), "local_index out of 2^10 range");

        // Convert the Vec<usize> into a SubIndex and then into a u128
        let sub_index: u128 = SubIndex::from(r.sub_index.clone()).into();

        // Pack frame_index and local_index into lo, and sub_index into hi
        let lo = frame_index | (local_index << 16);
        let hi = sub_index;

        Word::new([lo, hi])
    }
}

impl From<traced_value::Reference> for Word {
    fn from(r: traced_value::Reference) -> Self {
        (&r).into()
    }
}

impl From<&AccountAddress> for Word {
    fn from(addr: &AccountAddress) -> Self {
        let bytes = addr.into_bytes();

        let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());

        Word::new([lo, hi])
    }
}

impl From<&SimpleValue> for Word {
    fn from(value: &SimpleValue) -> Self {
        match value {
            SimpleValue::U8(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U16(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U32(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U64(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U128(u) => Word::new([*u, 0u128]),
            SimpleValue::U256(u) => {
                let bytes = u.to_le_bytes();
                let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
                Word::new([lo, hi])
            }
            SimpleValue::Bool(b) => Word::new([*b as u128, 0u128]),
            SimpleValue::Reference(r) => Word::from(r),
            SimpleValue::Address(a) => Word::from(a),
        }
    }
}

impl From<SimpleValue> for Word {
    fn from(value: SimpleValue) -> Self {
        (&value).into()
    }
}

impl From<&traced_value::Integer> for Word {
    fn from(value: &traced_value::Integer) -> Self {
        let (lo, hi) = match value {
            traced_value::Integer::U8(v) => (*v as u128, 0u128),
            traced_value::Integer::U16(v) => (*v as u128, 0u128),
            traced_value::Integer::U32(v) => (*v as u128, 0u128),
            traced_value::Integer::U64(v) => (*v as u128, 0u128),
            traced_value::Integer::U128(v) => (*v, 0u128),
            traced_value::Integer::U256(v) => {
                let bytes = v.to_le_bytes();
                let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
                (lo, hi)
            }
        };
        Word::new([lo, hi])
    }
}

impl From<traced_value::Integer> for Word {
    fn from(value: traced_value::Integer) -> Self {
        (&value).into()
    }
}

impl From<ValueHeader<u16>> for Word {
    fn from(header: ValueHeader<u16>) -> Self {
        let lo = header.flen as u128; // Store flen in the lower 16 bits of lo
        let hi = header.len as u128; // Store len in the lower 16 bits of hi

        Word::new([lo, hi])
    }
}

impl<F: Field> ToScalars<F> for Word {
    fn to_scalars(&self) -> Vec<F> {
        vec![F::from_u128(self.lo()), F::from_u128(self.hi())]
    }
}

impl<F: Field> Scalar<F> for Word {
    fn scalar(&self) -> F {
        F::from_u128(self.hi()) * pow_of_two::<F>(128) + F::from_u128(self.lo())
    }
}

/// A circuit word represented by two field elements: `lo` and `hi`.
pub type CircuitWord<F> = WordLoHi<F>;

/// Cells for storing a circuit word (`lo`, `hi`).
#[derive(Clone, Debug)]
pub struct WordCells<F> {
    cells: WordLoHiCell<F>,
    challenge: Expression<F>,
}

impl<F: Field> WordCells<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &mut CellManagerColumns,
        cell_manager: &mut CellManager<CMFixedHeightStrategy>,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let cells: [Cell<F>; 2] = cell_manager
            .query_cells(meta, cell_manager_columns, CellType::StoragePhase1, 2)
            .try_into()
            .unwrap();
        WordCells {
            cells: WordLoHiCell::new(cells),
            challenge: challenges.row_keccak_input(),
        }
    }
    pub fn cells(&self) -> [Cell<F>; 2] {
        let (lo, hi) = self.cells.to_lo_hi();
        [lo, hi]
    }
    pub fn expr(&self) -> Expression<F> {
        rlc::expr(&self.exprs(), self.challenge.clone())
    }
    pub fn exprs(&self) -> [Expression<F>; 2] {
        self.cells().map(|c| c.expr())
    }
}

impl<F: Field> WordCells<F> {
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Vec<F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert_eq!(
            value.len(),
            2,
            "WordCells::assign expects exactly 2 scalars"
        );
        let mut assigned = Vec::with_capacity(2);

        assigned.push(
            self.cells
                .lo()
                .assign(region, offset, Value::known(value[0].clone()))?,
        );
        assigned.push(
            self.cells
                .hi()
                .assign(region, offset, Value::known(value[1].clone()))?,
        );
        Ok(assigned)
    }

    pub fn assign_word(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Word,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let scalars: Vec<F> = value.to_scalars();
        self.assign(region, offset, scalars)
    }
}

#[derive(Clone, Debug)]
pub struct IntegerExpr<F>(WordLoHi<Expression<F>>);
impl<F: Field> IntegerExpr<F> {
    pub fn new(exprs: [Expression<F>; 2]) -> Self {
        Self(WordLoHi::new(exprs))
    }
    pub fn lo(&self) -> Expression<F> {
        self.0.lo()
    }
    pub fn hi(&self) -> Expression<F> {
        self.0.hi()
    }
    pub fn compress(&self) -> Expression<F> {
        self.0.compress()
    }
    pub fn select(
        selector: Expression<F>,
        when_true: IntegerExpr<F>,
        when_false: IntegerExpr<F>,
    ) -> IntegerExpr<F> {
        IntegerExpr(WordLoHi::select(selector, when_true.0, when_false.0))
    }
}

pub struct IndexExpr<F> {
    frame_index: Expression<F>,
    local_index: Expression<F>,
}
impl<F: Field> IndexExpr<F> {
    pub fn new(frame_index: Expression<F>, local_index: Expression<F>) -> Self {
        Self {
            frame_index,
            local_index,
        }
    }
    pub fn expr(&self) -> Expression<F> {
        self.frame_index.clone() + self.local_index.clone() * 2u64.pow(16).expr()
    }
}
pub struct ReferenceExpr<F> {
    index: Expression<F>,
    sub_index: Expression<F>,
}

impl<F: Field> ReferenceExpr<F> {
    pub fn index(&self) -> Expression<F> {
        self.index.clone()
    }
    pub fn sub_index(&self) -> Expression<F> {
        self.sub_index.clone()
    }
}

impl<F: Field> WordCells<F> {
    pub fn as_integer(&self) -> IntegerExpr<F> {
        IntegerExpr::new(self.exprs())
    }
    pub fn as_bool(&self) -> Expression<F> {
        self.cells.lo().expr()
    }
    pub fn as_header(&self) -> ValueHeader<Expression<F>> {
        ValueHeader {
            flen: self.cells.lo().expr(),
            len: self.cells.hi().expr(),
        }
    }
    pub fn as_reference(&self) -> ReferenceExpr<F> {
        ReferenceExpr {
            index: self.cells.lo().expr(),
            sub_index: self.cells.hi().expr(),
        }
    }
}

/// Helper for assigning a `u16`: splits it into low/high bytes and stores them in two cells to avoid a 16‑bit range check.
#[derive(Clone, Debug)]
pub struct WordU16Cells<F>(WordLoHiCell<F>);

impl<F: Field> WordU16Cells<F> {
    pub fn construct(cb: &mut impl ConstraintBuilder<F>) -> Self {
        Self(WordLoHiCell::new([cb.query_byte(), cb.query_byte()]))
    }
    pub fn new(cells: [Cell<F>; 2]) -> Self {
        Self(WordLoHiCell::new(cells))
    }
    pub fn cells(&self) -> [Cell<F>; 2] {
        [self.0.lo(), self.0.hi()]
    }
    pub fn lo(&self) -> Cell<F> {
        self.0.lo()
    }
    pub fn hi(&self) -> Cell<F> {
        self.0.hi()
    }
    pub fn expr(&self) -> Expression<F> {
        self.lo().expr() + self.hi().expr() * pow_of_two_expr(8)
    }
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: u16,
    ) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        self.0
            .lo()
            .assign(region, offset, Value::known(F::from(bytes[0] as u64)))?;
        self.0
            .hi()
            .assign(region, offset, Value::known(F::from(bytes[1] as u64)))?;
        Ok(())
    }
    pub fn assign_with_scalar(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lo: F,
        hi: F,
    ) -> Result<(), Error> {
        self.0.lo().assign(region, offset, Value::known(lo))?;
        self.0.hi().assign(region, offset, Value::known(hi))?;
        Ok(())
    }
}

/// Helper for assigning a `u10`: splits it into low/high bytes and stores them in two cells to avoid a 10‑bit range check.
#[derive(Clone, Debug)]
pub struct WordU10Cells<F>(WordLoHiCell<F>);

impl<F: Field> WordU10Cells<F> {
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        cell_manager_columns: &mut CellManagerColumns,
        cell_manager: &mut CellManager<CMFixedHeightStrategy>,
    ) -> Self {
        let lo = cell_manager.query_cell(meta, cell_manager_columns, CellType::Lookup(Table::U8));
        let hi = cell_manager.query_cell(meta, cell_manager_columns, CellType::Lookup(Table::U2));
        Self(WordLoHiCell::new([lo, hi]))
    }
    pub fn cells(&self) -> [Cell<F>; 2] {
        [self.0.lo(), self.0.hi()]
    }
    pub fn lo(&self) -> Cell<F> {
        self.0.lo()
    }
    pub fn hi(&self) -> Cell<F> {
        self.0.hi()
    }
    pub fn expr(&self) -> Expression<F> {
        self.lo().expr() + self.hi().expr() * pow_of_two_expr(8)
    }
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: u16,
    ) -> Result<(), Error> {
        assert!(value < 1024, "Value out of u10 range");
        let bytes = value.to_le_bytes();
        self.0
            .lo()
            .assign(region, offset, Value::known(F::from(bytes[0] as u64)))?;
        self.0
            .hi()
            .assign(region, offset, Value::known(F::from(bytes[1] as u64)))?;
        Ok(())
    }
    pub fn assign_with_scalar(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lo: F,
        hi: F,
    ) -> Result<(), Error> {
        self.0.lo().assign(region, offset, Value::known(lo))?;
        self.0.hi().assign(region, offset, Value::known(hi))?;
        Ok(())
    }
}
