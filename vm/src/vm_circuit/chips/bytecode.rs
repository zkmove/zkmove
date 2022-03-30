use crate::vm_circuit::chips::bytecode::{
    _mod::Mod, add::Add, and::And, br_false::BrFalse, br_true::BrTrue, branch::Branch,
    copy_loc::CopyLoc, div::Div, eq::Eq, ld_false::LdFalse, ld_true::LdTrue, ldu128::LdU128,
    ldu64::LdU64, ldu8::LdU8, move_loc::MoveLoc, mul::Mul, neq::Neq, not::Not, or::Or, pop::Pop,
    ret::Ret, st_loc::StLoc, sub::Sub,
};
use crate::vm_circuit::chips::lookup_tables::RWLookup;
use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_binary_format::file_format::Bytecode;

pub mod _mod;
pub mod add;
pub mod and;
pub mod br_false;
pub mod br_true;
pub mod branch;
pub mod common;
pub mod copy_loc;
pub mod div;
pub mod eq;
pub mod ld_false;
pub mod ld_true;
pub mod ldu128;
pub mod ldu64;
pub mod ldu8;
pub mod move_loc;
pub mod mul;
pub mod neq;
pub mod not;
pub mod or;
pub mod pop;
pub mod ret;
pub mod st_loc;
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
    Eq,
    Neq,
    And,
    Or,
    Not,
    MoveLoc,
    StLoc,
    Branch,
    BrTrue,
    BrFalse,
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
            Self::Eq,
            Self::Neq,
            Self::And,
            Self::Or,
            Self::Not,
            Self::MoveLoc,
            Self::StLoc,
            Self::Branch,
            Self::BrTrue,
            Self::BrFalse,
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
            Opcode::Eq => Eq::configure(cells, constraints, rw_lookups),
            Opcode::Neq => Neq::configure(cells, constraints, rw_lookups),
            Opcode::And => And::configure(cells, constraints, rw_lookups),
            Opcode::Or => Or::configure(cells, constraints, rw_lookups),
            Opcode::Not => Not::configure(cells, constraints, rw_lookups),
            Opcode::MoveLoc => MoveLoc::configure(cells, constraints, rw_lookups),
            Opcode::StLoc => StLoc::configure(cells, constraints, rw_lookups),
            Opcode::Branch => Branch::configure(cells, constraints, rw_lookups),
            Opcode::BrTrue => BrTrue::configure(cells, constraints, rw_lookups),
            Opcode::BrFalse => BrFalse::configure(cells, constraints, rw_lookups),
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
            Opcode::Eq => Eq::assign(region, offset, step, rw_table, cells)?,
            Opcode::Neq => Neq::assign(region, offset, step, rw_table, cells)?,
            Opcode::And => And::assign(region, offset, step, rw_table, cells)?,
            Opcode::Or => Or::assign(region, offset, step, rw_table, cells)?,
            Opcode::Not => Not::assign(region, offset, step, rw_table, cells)?,
            Opcode::MoveLoc => MoveLoc::assign(region, offset, step, rw_table, cells)?,
            Opcode::StLoc => StLoc::assign(region, offset, step, rw_table, cells)?,
            Opcode::Branch => Branch::assign(region, offset, step, rw_table, cells)?,
            Opcode::BrTrue => BrTrue::assign(region, offset, step, rw_table, cells)?,
            Opcode::BrFalse => BrFalse::assign(region, offset, step, rw_table, cells)?,
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
            Bytecode::Eq => Opcode::Eq,
            Bytecode::Neq => Opcode::Neq,
            Bytecode::And => Opcode::And,
            Bytecode::Or => Opcode::Or,
            Bytecode::Not => Opcode::Not,
            Bytecode::MoveLoc(_) => Opcode::MoveLoc,
            Bytecode::StLoc(_) => Opcode::StLoc,
            Bytecode::Branch(_) => Opcode::Branch,
            Bytecode::BrTrue(_) => Opcode::BrTrue,
            Bytecode::BrFalse(_) => Opcode::BrFalse,
            _ => unimplemented!(),
        }
    }
}
