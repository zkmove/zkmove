use crate::vm_circuit::chips::bytecode::_mod::Mod;
use crate::vm_circuit::chips::bytecode::add::Add;
use crate::vm_circuit::chips::bytecode::copy_loc::CopyLoc;
use crate::vm_circuit::chips::bytecode::div::Div;
use crate::vm_circuit::chips::bytecode::ld_false::LdFalse;
use crate::vm_circuit::chips::bytecode::ld_true::LdTrue;
use crate::vm_circuit::chips::bytecode::ldu128::LdU128;
use crate::vm_circuit::chips::bytecode::ldu64::LdU64;
use crate::vm_circuit::chips::bytecode::ldu8::LdU8;
use crate::vm_circuit::chips::bytecode::mul::Mul;
use crate::vm_circuit::chips::bytecode::pop::Pop;
use crate::vm_circuit::chips::bytecode::ret::Ret;
use crate::vm_circuit::chips::bytecode::sub::Sub;
use crate::vm_circuit::chips::lookup_tables::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_binary_format::file_format::Bytecode;

pub mod _mod;
pub mod add;
pub mod common;
pub mod copy_loc;
pub mod div;
pub mod ld_false;
pub mod ld_true;
pub mod ldu128;
pub mod ldu64;
pub mod ldu8;
pub mod mul;
pub mod pop;
pub mod ret;
pub mod sub;

pub trait BytecodeInterface<F: FieldExt> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    );

    fn assign(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error>;
}

// supported opcode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Opcode {
    LdU8 = 0,
    LdU64,
    LdU128,
    Pop,
    Ret,
    Add,
    Mul,
    CopyLoc,
    Sub,
    Div,
    Mod,
    LdTrue,
    LdFalse,
}

impl Opcode {
    pub fn index(&self) -> usize {
        *self as usize
    }

    pub fn iter() -> impl Iterator<Item = Self> {
        [
            Self::LdU8,
            Self::LdU64,
            Self::LdU128,
            Self::Pop,
            Self::Ret,
            Self::Add,
            Self::Mul,
            Self::CopyLoc,
            Self::Sub,
            Self::Div,
            Self::Mod,
            Self::LdTrue,
            Self::LdFalse,
        ]
        .iter()
        .copied()
    }

    pub fn total_numbers() -> usize {
        Self::iter().count()
    }

    pub fn configure<F: FieldExt>(
        &self,
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
    ) {
        match self {
            Opcode::LdU8 => LdU8::configure(cells, constraints, rw_lookups),
            Opcode::LdU64 => LdU64::configure(cells, constraints, rw_lookups),
            Opcode::LdU128 => LdU128::configure(cells, constraints, rw_lookups),
            Opcode::Pop => Pop::configure(cells, constraints, rw_lookups),
            Opcode::Ret => Ret::configure(cells, constraints, rw_lookups),
            Opcode::Add => Add::configure(cells, constraints, rw_lookups),
            Opcode::Mul => Mul::configure(cells, constraints, rw_lookups),
            Opcode::CopyLoc => CopyLoc::configure(cells, constraints, rw_lookups),
            Opcode::Sub => Sub::configure(cells, constraints, rw_lookups),
            Opcode::Div => Div::configure(cells, constraints, rw_lookups),
            Opcode::Mod => Mod::configure(cells, constraints, rw_lookups),
            Opcode::LdTrue => LdTrue::configure(cells, constraints, rw_lookups),
            Opcode::LdFalse => LdFalse::configure(cells, constraints, rw_lookups),
        }
    }

    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        match self {
            Opcode::LdU8 => LdU8::assign(region, offset, step, rw_table, cells)?,
            Opcode::LdU64 => LdU64::assign(region, offset, step, rw_table, cells)?,
            Opcode::LdU128 => LdU128::assign(region, offset, step, rw_table, cells)?,
            Opcode::Pop => Pop::assign(region, offset, step, rw_table, cells)?,
            Opcode::Ret => Ret::assign(region, offset, step, rw_table, cells)?,
            Opcode::Add => Add::assign(region, offset, step, rw_table, cells)?,
            Opcode::Mul => Mul::assign(region, offset, step, rw_table, cells)?,
            Opcode::CopyLoc => CopyLoc::assign(region, offset, step, rw_table, cells)?,
            Opcode::Sub => Sub::assign(region, offset, step, rw_table, cells)?,
            Opcode::Div => Div::assign(region, offset, step, rw_table, cells)?,
            Opcode::Mod => Mod::assign(region, offset, step, rw_table, cells)?,
            Opcode::LdTrue => LdTrue::assign(region, offset, step, rw_table, cells)?,
            Opcode::LdFalse => LdFalse::assign(region, offset, step, rw_table, cells)?,
        }
        Ok(())
    }
}

impl From<Bytecode> for Opcode {
    fn from(bytecode: Bytecode) -> Opcode {
        match bytecode {
            Bytecode::LdU8(_) => Opcode::LdU8,
            Bytecode::LdU64(_) => Opcode::LdU64,
            Bytecode::LdU128(_) => Opcode::LdU128,
            Bytecode::Pop => Opcode::Pop,
            Bytecode::Ret => Opcode::Ret,
            Bytecode::Add => Opcode::Add,
            Bytecode::Mul => Opcode::Mul,
            Bytecode::CopyLoc(_) => Opcode::CopyLoc,
            Bytecode::Sub => Opcode::Sub,
            Bytecode::Div => Opcode::Div,
            Bytecode::Mod => Opcode::Mod,
            Bytecode::LdTrue => Opcode::LdTrue,
            Bytecode::LdFalse => Opcode::LdFalse,
            _ => unimplemented!(),
        }
    }
}
