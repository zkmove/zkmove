use crate::chips::execution_chip::utils::{CellManager, CellType};
use crate::chips::utilities::{Cell, Expr};
use fields::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use std::iter;

/// Dynamic selector that generates expressions of degree 2 to select from N
/// possible targets using N/2 + 1 cells.
#[derive(Clone, Debug)]
pub(crate) struct DynamicSelectorHalf<F> {
    /// N value: how many possible targets this selector supports.
    count: usize,
    /// Whether the target is odd.  `target % 2 == 1`.
    pub(crate) target_odd: Cell<F>,
    /// Whether the target belongs to each consecutive pair of targets.
    /// `in [0, 1], in [2, 3], in [4, 5], ...`
    pub(crate) target_pairs: Vec<Cell<F>>,
}

impl<F: FieldExt> DynamicSelectorHalf<F> {
    pub(crate) fn new(cell_manager: &mut CellManager<F>, count: usize) -> Self {
        let target_pairs = cell_manager.allocate_cells(CellType::CustomGate, (count + 1) / 2);
        let target_odd = cell_manager.alloc_cell(CellType::CustomGate);
        Self {
            count,
            target_pairs,
            target_odd,
        }
    }

    /// Return the list of constraints that configure this "gadget".
    pub(crate) fn configure(&self) -> Vec<(&'static str, Expression<F>)> {
        // Only one of target_pairs should be enabled
        let sum_to_one = (
            "Only one of target_pairs should be enabled",
            self.target_pairs
                .iter()
                .fold(1u64.expr(), |acc, cell| acc - cell.expr()),
        );
        // Cells representation for target_pairs and target_odd should be bool.
        let bool_checks = iter::once(&self.target_odd)
            .chain(&self.target_pairs)
            .map(|cell| {
                (
                    "Representation for target_pairs and target_odd should be bool",
                    cell.expr() * (1u64.expr() - cell.expr()),
                )
            });
        let mut constraints: Vec<(&'static str, Expression<F>)> =
            iter::once(sum_to_one).chain(bool_checks).collect();
        // In case count is odd, we must forbid selecting N+1 with (odd = 1,
        // target_pairs[-1] = 1)
        if self.count % 2 == 1 {
            constraints.push((
                "Forbid N+1 target when N is odd",
                self.target_odd.expr() * self.target_pairs[self.count / 2].expr(),
            ));
        }
        constraints
    }

    pub(crate) fn selector(&self, targets: impl IntoIterator<Item = usize>) -> Expression<F> {
        targets
            .into_iter()
            .map(|target| {
                let odd = target % 2 == 1;
                let pair_index = target / 2;
                (if odd {
                    self.target_odd.expr()
                } else {
                    1.expr() - self.target_odd.expr()
                }) * self.target_pairs[pair_index].expr()
            })
            .reduce(|acc, expr| acc + expr)
            .expect("Select some Targets")
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        target: usize,
    ) -> Result<(), Error> {
        let odd = target % 2 == 1;
        let pair_index = target / 2;
        self.target_odd
            .assign(region, offset, Some(if odd { F::ONE } else { F::ZERO }))?;
        for (index, cell) in self.target_pairs.iter().enumerate() {
            cell.assign(
                region,
                offset,
                Some(if index == pair_index { F::ONE } else { F::ZERO }),
            )?;
        }
        Ok(())
    }
}
