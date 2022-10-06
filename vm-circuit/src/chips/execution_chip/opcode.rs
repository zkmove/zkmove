use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::instructions::{
    _mod::Mod, abort::Abort, add::Add, and::And, br_false::BrFalse, br_true::BrTrue,
    branch::Branch, call::Call, copy_loc::CopyLoc, div::Div, eq::Eq, imm_borrow_loc::ImmBorrowLoc,
    ld_false::LdFalse, ld_true::LdTrue, ldu128::LdU128, ldu64::LdU64, ldu8::LdU8, lt::Lt,
    move_loc::MoveLoc, mul::Mul, mut_borrow_loc::MutBorrowLoc, neq::Neq, nop::Nop, not::Not,
    or::Or, pop::Pop, ret::Ret, st_loc::StLoc, stop::Stop, sub::Sub,
};
use crate::chips::execution_chip::lookup_tables::{BytecodeLookup, RWLookup};
use crate::chips::execution_chip::step_chip::StepChipCells;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RWOperations;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_binary_format::file_format::Bytecode;

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
    Call,
    Abort,
    Lt,
    Stop,
    Nop,
    MutBorrowLoc,
    ImmBorrowLoc,
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
            Self::Call,
            Self::Abort,
            Self::Lt,
            Self::Stop,
            Self::Nop,
            Self::MutBorrowLoc,
            Self::ImmBorrowLoc,
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
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
    ) {
        match self {
            Opcode::LdU8 => LdU8::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::LdU64 => LdU64::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::LdU128 => LdU128::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Pop => Pop::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Ret => Ret::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Add => Add::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Mul => Mul::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::CopyLoc => CopyLoc::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Sub => Sub::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Div => Div::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Mod => Mod::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::LdTrue => LdTrue::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::LdFalse => LdFalse::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Eq => Eq::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Neq => Neq::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::And => And::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Or => Or::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Not => Not::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::MoveLoc => MoveLoc::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::StLoc => StLoc::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Branch => Branch::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::BrTrue => BrTrue::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::BrFalse => BrFalse::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Call => Call::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Abort => Abort::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Lt => Lt::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Stop => Stop::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Nop => Nop::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::MutBorrowLoc => {
                MutBorrowLoc::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::ImmBorrowLoc => {
                ImmBorrowLoc::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
        }
    }

    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep<F>,
        rw_operations: &RWOperations<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        match self {
            Opcode::LdU8 => LdU8::assign(region, offset, step, rw_operations, cells)?,
            Opcode::LdU64 => LdU64::assign(region, offset, step, rw_operations, cells)?,
            Opcode::LdU128 => LdU128::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Pop => Pop::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Ret => Ret::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Add => Add::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Mul => Mul::assign(region, offset, step, rw_operations, cells)?,
            Opcode::CopyLoc => CopyLoc::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Sub => Sub::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Div => Div::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Mod => Mod::assign(region, offset, step, rw_operations, cells)?,
            Opcode::LdTrue => LdTrue::assign(region, offset, step, rw_operations, cells)?,
            Opcode::LdFalse => LdFalse::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Eq => Eq::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Neq => Neq::assign(region, offset, step, rw_operations, cells)?,
            Opcode::And => And::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Or => Or::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Not => Not::assign(region, offset, step, rw_operations, cells)?,
            Opcode::MoveLoc => MoveLoc::assign(region, offset, step, rw_operations, cells)?,
            Opcode::StLoc => StLoc::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Branch => Branch::assign(region, offset, step, rw_operations, cells)?,
            Opcode::BrTrue => BrTrue::assign(region, offset, step, rw_operations, cells)?,
            Opcode::BrFalse => BrFalse::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Call => Call::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Abort => Abort::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Lt => Lt::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Stop => Stop::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Nop => Nop::assign(region, offset, step, rw_operations, cells)?,
            Opcode::MutBorrowLoc => {
                MutBorrowLoc::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::ImmBorrowLoc => {
                ImmBorrowLoc::assign(region, offset, step, rw_operations, cells)?
            }
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
            Bytecode::Call(_) => Opcode::Call,
            Bytecode::Abort => Opcode::Abort,
            Bytecode::Lt => Opcode::Lt,
            Bytecode::MutBorrowLoc(_) => Opcode::MutBorrowLoc,
            Bytecode::ImmBorrowLoc(_) => Opcode::ImmBorrowLoc,
            _ => unimplemented!(),
        }
    }
}
