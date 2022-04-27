// Copyright (c) zkMove Authors

use crate::vm_circuit::chips::utilities::*;
use crate::vm_circuit::circuit_inputs::BytecodeInfo;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Region};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use std::collections::VecDeque;
use std::marker::PhantomData;

pub const BYTECODE_CHIP_WIDTH: usize = 6;

#[derive(Clone, Debug)]
pub struct BytecodeCells<F: FieldExt> {
    pub module_index: Cell<F>,
    pub function_index: Cell<F>,
    pub pc: Cell<F>,
    pub opcode: Cell<F>,
    pub operand: Cell<F>,
    pub hash: Cell<F>,

    pub prev_module_index: Cell<F>,
    pub prev_function_index: Cell<F>,
    pub prev_pc: Cell<F>,
    pub prev_opcode: Cell<F>,
    pub prev_operand: Cell<F>,
    pub prev_hash: Cell<F>,
}

#[derive(Debug, Clone)]
pub struct BytecodeChipConfig<F: FieldExt> {
    pub advices: [Column<Advice>; BYTECODE_CHIP_WIDTH],
    pub cells: BytecodeCells<F>,
    pub s_first_bytecode: Selector,
    pub s_bytecode: Selector,
}

pub struct BytecodeChip<F: FieldExt> {
    pub config: BytecodeChipConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for BytecodeChip<F> {
    type Config = BytecodeChipConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> BytecodeChip<F> {
    pub fn construct(
        config: <Self as Chip<F>>::Config,
        _loaded: <Self as Chip<F>>::Loaded,
    ) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; BYTECODE_CHIP_WIDTH],
    ) -> <Self as Chip<F>>::Config {
        let mut cells = VecDeque::with_capacity(BYTECODE_CHIP_WIDTH * 2);
        meta.create_gate("bytecode chip", |meta| {
            for i in 0..BYTECODE_CHIP_WIDTH {
                let column_index = i;
                let rotation = 0;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            for i in 0..BYTECODE_CHIP_WIDTH {
                let column_index = i;
                let rotation = -1;
                cells.push_back(Cell::new(meta, advices[column_index], rotation))
            }

            vec![Expression::Constant(F::zero())]
        });

        let cells = BytecodeCells {
            module_index: cells.pop_front().unwrap(),
            function_index: cells.pop_front().unwrap(),
            pc: cells.pop_front().unwrap(),
            opcode: cells.pop_front().unwrap(),
            operand: cells.pop_front().unwrap(),
            hash: cells.pop_front().unwrap(),

            prev_module_index: cells.pop_front().unwrap(),
            prev_function_index: cells.pop_front().unwrap(),
            prev_pc: cells.pop_front().unwrap(),
            prev_opcode: cells.pop_front().unwrap(),
            prev_operand: cells.pop_front().unwrap(),
            prev_hash: cells.pop_front().unwrap(),
        };

        let s_first_bytecode = meta.complex_selector();
        Self::constrain_bytecode_hash(meta, s_first_bytecode, &cells, true);

        let s_bytecode = meta.complex_selector();
        Self::constrain_bytecode_hash(meta, s_bytecode, &cells, false);

        BytecodeChipConfig {
            advices,
            cells,
            s_first_bytecode,
            s_bytecode,
        }
    }

    fn constrain_bytecode_hash(
        _meta: &mut ConstraintSystem<F>,
        _selector: Selector,
        _cells: &BytecodeCells<F>,
        _is_first_bytecode: bool,
    ) {
        // constrain: cells.hash == hash_func(prev_hash, module_index, function_index, pc, opcode, operand)
        // for the first bytecode, prev_hash = 0
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        bytecode: &BytecodeInfo,
        hash: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let fields: Vec<F> = bytecode.into();
        self.config
            .cells
            .module_index
            .assign(region, offset, Some(fields[0]))?;

        self.config
            .cells
            .function_index
            .assign(region, offset, Some(fields[1]))?;

        self.config
            .cells
            .pc
            .assign(region, offset, Some(fields[2]))?;

        self.config
            .cells
            .opcode
            .assign(region, offset, Some(fields[3]))?;

        self.config
            .cells
            .operand
            .assign(region, offset, Some(fields[4]))?;

        let assigned_hash_cell = self
            .config
            .cells
            .operand
            .assign(region, offset, Some(hash))?;

        Ok(assigned_hash_cell)
    }
}
