use std::collections::HashMap;

use crate::chips::execution_chip_v2::lookup_table::Table;
use crate::utils::cached_region::CachedRegion;
use crate::utils::query_expression;
use gadgets::util::Expr;
use halo2_proofs::plonk::Instance;
use halo2_proofs::{
    circuit::{AssignedCell, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;
use types::Field;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// CellType represent a category of cell (and column).
pub(crate) enum CellType {
    StoragePhase0,
    StoragePhase1,
    StoragePhase1EnableEquality,
    Lookup(Table),
}

impl CellType {
    pub(crate) fn all() -> Vec<CellType> {
        [
            Self::StoragePhase0,
            Self::StoragePhase1,
            Self::StoragePhase1EnableEquality,
        ]
        .into_iter()
        .chain(Table::iter().map(CellType::Lookup))
        .collect()
    }
}

impl CellType {
    // TODO: find a better way to do this.
    pub fn phase(&self) -> u8 {
        match self {
            CellType::StoragePhase0 => 0,
            CellType::StoragePhase1 | CellType::StoragePhase1EnableEquality => 1,
            CellType::Lookup(t) => match t {
                Table::Nibble | Table::U8 | Table::U10 => 2,
                #[cfg(feature = "table-u16")]
                Table::U16 => 2,
                _ => 2,
            },
        }
    }
}

impl CellType {
    // The phase that given `Expression` becomes evaluateable.
    pub(crate) fn expr_phase<F: Field>(expr: &Expression<F>) -> u8 {
        use Expression::*;
        match expr {
            Challenge(challenge) => challenge.phase() + 1,
            Advice(query) => query.phase(),
            Constant(_) | Selector(_) | Fixed(_) | Instance(_) => 0,
            Negated(a) | Expression::Scaled(a, _) => Self::expr_phase(a),
            Sum(a, b) | Product(a, b) => std::cmp::max(Self::expr_phase(a), Self::expr_phase(b)),
        }
    }

    /// Return the storage phase of phase.
    pub(crate) fn storage_for_phase(phase: u8) -> CellType {
        match phase {
            0 => CellType::StoragePhase0,
            1 => CellType::StoragePhase1,
            _ => unreachable!(),
        }
    }

    /// Return the storage cell of the expression.
    pub(crate) fn storage_for_expr<F: Field>(expr: &Expression<F>) -> CellType {
        Self::storage_for_phase(Self::expr_phase::<F>(expr))
    }
}

#[derive(Clone, Debug)]
/// Cell is a (column, rotation) pair that has been placed and queried by the Cell Manager.
pub struct Cell<F> {
    expression: Expression<F>,
    column: Column<Advice>,
    rotation: isize,
}

impl<F: Field> Cell<F> {
    /// Creates a Cell from VirtualCells.
    #[cfg(not(feature = "test-circuits"))]
    pub fn new(column: Column<Advice>, rotation: isize) -> Cell<F> {
        Cell {
            expression: column.query_cell(Rotation(rotation as i32)),
            column,
            rotation,
        }
    }

    /// Creates a Cell from ConstraintSystem.
    #[cfg(feature = "test-circuits")]
    pub fn new_from_cs(
        meta: &mut ConstraintSystem<F>,
        column: Column<Advice>,
        rotation: isize,
    ) -> Cell<F> {
        query_expression(meta, |meta| Cell {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
        })
    }

    /// Assigns a Cell during witness generation.
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column,
            (offset as isize + self.rotation) as usize,
            || value,
        )
    }
    /// Assigns a Cell from instance.
    pub(crate) fn assign_from_instance(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        instance: Column<Instance>,
        row: usize,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice_from_instance(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            instance,
            row,
            self.column,
            (offset as isize + self.rotation) as usize,
        )
    }
    #[cfg(feature = "test-circuits")]
    pub(crate) fn at_offset(&self, meta: &mut ConstraintSystem<F>, offset: i32) -> Self {
        Self::new_from_cs(meta, self.column, self.rotation + offset as isize)
    }
    #[cfg(not(feature = "test-circuits"))]
    pub(crate) fn at_offset(&self, offset: i32) -> Self {
        Self::new(self.column, self.rotation + offset as isize)
    }
}

impl<F> Cell<F> {
    pub(crate) fn get_column_idx(&self) -> usize {
        self.column.index()
    }
    pub(crate) fn get_column(&self) -> Column<Advice> {
        self.column
    }

    pub(crate) fn get_rotation(&self) -> isize {
        self.rotation
    }
}

impl<F: Field> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

impl<F: Field> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

#[derive(Debug, Clone)]
/// CellColumn represent a column that is managed by a Cell Manager.
pub(crate) struct CellColumn {
    pub advice: Column<Advice>,
    pub cell_type: CellType,
    pub idx: usize,
}

impl CellColumn {
    /// Creates a CellColumn from a Column and Cell Type.
    pub fn new(advice: Column<Advice>, cell_type: CellType, idx: usize) -> CellColumn {
        CellColumn {
            advice,
            cell_type,
            idx,
        }
    }

    /// Queries column at rotation 0.
    pub fn expr<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Expression<F> {
        query_expression(meta, |meta| meta.query_advice(self.advice, Rotation::cur()))
    }

    pub fn expr_vc<F: Field>(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_advice(self.advice, Rotation::cur())
    }
}

pub(crate) struct CellPlacement {
    pub column: CellColumn,
    pub rotation: isize,
}

/// CellPlacementStrategy is a strategy to place cells by the Cell Manager.
pub(crate) trait CellPlacementStrategy {
    /// Stats is the type of the returned statistics.
    type Stats;

    /// Affinity is used as extra information when querying cells that is used for their correct
    /// placement.
    type Affinity;

    /// The cell manager will call on_creation when built, so the columns can be set up by the
    /// strategy.
    fn on_creation(&mut self, columns: &mut CellManagerColumns);

    /// Queries a cell from the strategy.
    fn place_cell<F: Field>(
        &mut self,
        columns: &mut CellManagerColumns,
        meta: &mut ConstraintSystem<F>,
        cell_type: CellType,
    ) -> CellPlacement;

    /// Queries a cell from the strategy, using an affinity attribute.
    fn place_cell_with_affinity<F: Field>(
        &mut self,
        columns: &mut CellManagerColumns,
        meta: &mut ConstraintSystem<F>,
        cell_type: CellType,
        affinity: Self::Affinity,
    ) -> CellPlacement;

    /// Gets the current height of the cell manager, the max rotation of any cell (without
    /// considering offset).
    fn get_height(&self) -> usize;

    /// Returns stats about this cells placement.
    fn get_stats(&self, columns: &CellManagerColumns) -> Self::Stats;
}

/// CellManagerColumns contains the columns of the Cell Manager and is the main interface between
/// the Cell Manager and the used strategy.
#[derive(Default, Debug, Clone)]
pub(crate) struct CellManagerColumns {
    columns: HashMap<CellType, Vec<CellColumn>>,
    columns_list: Vec<CellColumn>,
}

impl CellManagerColumns {
    /// Adds a column.
    pub fn add_column(&mut self, cell_type: CellType, column: Column<Advice>) {
        let idx = self.columns_list.len();
        let cell_column = CellColumn::new(column, cell_type, idx);

        self.columns_list.push(cell_column.clone());
        self.columns
            .entry(cell_type)
            .and_modify(|columns| columns.push(cell_column.clone()))
            .or_insert(vec![cell_column]);
    }

    /// Get the number of columns for a given Cell Type.
    pub fn get_cell_type_width(&self, cell_type: CellType) -> usize {
        if let Some(columns) = self.columns.get(&cell_type) {
            columns.len()
        } else {
            0
        }
    }

    /// Returns a column of a given cell type and index among all columns of that cell type.
    pub fn get_column(&self, cell_type: CellType, column_idx: usize) -> Option<&CellColumn> {
        if let Some(columns) = self.columns.get(&cell_type) {
            columns.get(column_idx)
        } else {
            None
        }
    }

    /// Returns an array with all the columns.
    pub fn columns(&self) -> Vec<CellColumn> {
        self.columns_list.clone()
    }

    #[allow(dead_code, reason = "under active development")]
    /// Returns the number of columns.
    pub fn get_width(&self) -> usize {
        self.columns_list.len()
    }
}

/// CellManager places and return cells in an area of the plonkish table given a strategy.
#[derive(Clone, Debug)]
pub(crate) struct CellManager<S: CellPlacementStrategy> {
    strategy: S,
}

impl<Stats, S: CellPlacementStrategy<Stats = Stats>> CellManager<S> {
    /// Creates a Cell Manager with a given strategy.
    pub fn new(mut strategy: S, cell_manager_columns: &mut CellManagerColumns) -> CellManager<S> {
        strategy.on_creation(cell_manager_columns);
        CellManager { strategy }
    }

    /// Places, and returns a Cell for a given cell type following the strategy.
    pub fn query_cell<F: Field>(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        columns: &mut CellManagerColumns,
        cell_type: CellType,
    ) -> Cell<F> {
        let placement = self.strategy.place_cell(columns, meta, cell_type);
        #[cfg(feature = "test-circuits")]
        {
            Cell::new_from_cs(meta, placement.column.advice, placement.rotation)
        }
        #[cfg(not(feature = "test-circuits"))]
        {
            Cell::new(placement.column.advice, placement.rotation)
        }
    }

    pub fn query_cell_with_affinity<F: Field>(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        columns: &mut CellManagerColumns,
        cell_type: CellType,
        affinity: S::Affinity,
    ) -> Cell<F> {
        let placement = self
            .strategy
            .place_cell_with_affinity(columns, meta, cell_type, affinity);

        #[cfg(feature = "test-circuits")]
        {
            Cell::new_from_cs(meta, placement.column.advice, placement.rotation)
        }
        #[cfg(not(feature = "test-circuits"))]
        {
            Cell::new(placement.column.advice, placement.rotation)
        }
    }

    /// Places, and returns `count` Cells for a given cell type following the strategy.
    pub fn query_cells<F: Field>(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        columns: &mut CellManagerColumns,
        cell_type: CellType,
        count: usize,
    ) -> Vec<Cell<F>> {
        (0..count)
            .map(|_| self.query_cell(meta, columns, cell_type))
            .collect()
    }

    /// Gets the current height of the cell manager, the max rotation of any cell (without
    /// considering offset).
    pub fn get_height(&self) -> usize {
        self.strategy.get_height()
    }
    /// Returns the statistics about this Cell Manager.
    pub fn get_stats(&self, columns: &CellManagerColumns) -> Stats {
        self.strategy.get_stats(columns)
    }

    pub fn get_strategy(&mut self) -> &mut S {
        &mut self.strategy
    }
}
