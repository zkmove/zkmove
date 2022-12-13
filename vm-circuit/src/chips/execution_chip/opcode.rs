use crate::chips::execution_chip::instructions::Instructions;
use crate::chips::execution_chip::instructions::{
    _mod::Mod, abort::Abort, add::Add, and::And, br_false::BrFalse, br_true::BrTrue,
    branch::Branch, call::Call, castu128::CastU128, castu64::CastU64, castu8::CastU8,
    copy_loc::CopyLoc, div::Div, eq::Eq, exists::Exists, freeze_ref::FreezeRef, ge::Ge, gt::Gt,
    imm_borrow_field::ImmBorrowField, imm_borrow_global::ImmBorrowGlobal,
    imm_borrow_loc::ImmBorrowLoc, ld_false::LdFalse, ld_true::LdTrue, ldu128::LdU128, ldu64::LdU64,
    ldu8::LdU8, le::Le, lt::Lt, move_from::MoveFrom, move_loc::MoveLoc, move_to::MoveTo, mul::Mul,
    mut_borrow_field::MutBorrowField, mut_borrow_global::MutBorrowGlobal,
    mut_borrow_loc::MutBorrowLoc, neq::Neq, nop::Nop, not::Not, or::Or, pack::Pack, pop::Pop,
    read_ref::ReadRef, ret::Ret, st_loc::StLoc, stop::Stop, sub::Sub, unpack::Unpack,
    write_ref::WriteRef,
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
    CastU8,
    CastU64,
    CastU128,
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
    Le,
    Lt,
    Ge,
    Gt,
    Pack,
    Unpack,
    MutBorrowLoc,
    ImmBorrowLoc,
    ReadRef,
    WriteRef,
    FreezeRef,
    ImmBorrowField,
    MutBorrowField,
    MoveFrom,
    MoveTo,
    Exists,
    ImmBorrowGlobal,
    MutBorrowGlobal,
    Stop,
    Nop,
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
            Self::CastU8,
            Self::CastU64,
            Self::CastU128,
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
            Self::Le,
            Self::Lt,
            Self::Ge,
            Self::Gt,
            Self::Pack,
            Self::Unpack,
            Self::MutBorrowLoc,
            Self::ImmBorrowLoc,
            Self::ReadRef,
            Self::WriteRef,
            Self::FreezeRef,
            Self::ImmBorrowField,
            Self::MutBorrowField,
            Self::MoveFrom,
            Self::MoveTo,
            Self::Exists,
            Self::ImmBorrowGlobal,
            Self::MutBorrowGlobal,
            Self::Stop,
            Self::Nop,
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
            Opcode::CastU8 => CastU8::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::CastU64 => CastU64::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::CastU128 => {
                CastU128::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
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
            Opcode::Le => Le::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Lt => Lt::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Ge => Ge::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Gt => Gt::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Pack => Pack::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Unpack => Unpack::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::MutBorrowLoc => {
                MutBorrowLoc::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::ImmBorrowLoc => {
                ImmBorrowLoc::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::ReadRef => ReadRef::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::WriteRef => {
                WriteRef::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::FreezeRef => {
                FreezeRef::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::ImmBorrowField => {
                ImmBorrowField::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::MutBorrowField => {
                MutBorrowField::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::MoveFrom => {
                MoveFrom::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::MoveTo => MoveTo::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Exists => Exists::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::ImmBorrowGlobal => {
                ImmBorrowGlobal::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::MutBorrowGlobal => {
                MutBorrowGlobal::configure(cells, constraints, rw_lookups, bytecode_lookups)
            }
            Opcode::Stop => Stop::configure(cells, constraints, rw_lookups, bytecode_lookups),
            Opcode::Nop => Nop::configure(cells, constraints, rw_lookups, bytecode_lookups),
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
            Opcode::CastU8 => CastU8::assign(region, offset, step, rw_operations, cells)?,
            Opcode::CastU64 => CastU64::assign(region, offset, step, rw_operations, cells)?,
            Opcode::CastU128 => CastU128::assign(region, offset, step, rw_operations, cells)?,
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
            Opcode::Le => Le::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Lt => Lt::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Ge => Ge::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Gt => Gt::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Pack => Pack::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Unpack => Unpack::assign(region, offset, step, rw_operations, cells)?,
            Opcode::MutBorrowLoc => {
                MutBorrowLoc::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::ImmBorrowLoc => {
                ImmBorrowLoc::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::ReadRef => ReadRef::assign(region, offset, step, rw_operations, cells)?,
            Opcode::WriteRef => WriteRef::assign(region, offset, step, rw_operations, cells)?,
            Opcode::FreezeRef => FreezeRef::assign(region, offset, step, rw_operations, cells)?,
            Opcode::ImmBorrowField => {
                ImmBorrowField::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::MutBorrowField => {
                MutBorrowField::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::MoveFrom => MoveFrom::assign(region, offset, step, rw_operations, cells)?,
            Opcode::MoveTo => MoveTo::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Exists => Exists::assign(region, offset, step, rw_operations, cells)?,
            Opcode::ImmBorrowGlobal => {
                ImmBorrowGlobal::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::MutBorrowGlobal => {
                MutBorrowGlobal::assign(region, offset, step, rw_operations, cells)?
            }
            Opcode::Stop => Stop::assign(region, offset, step, rw_operations, cells)?,
            Opcode::Nop => Nop::assign(region, offset, step, rw_operations, cells)?,
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
            Bytecode::CastU8 => Opcode::CastU8,
            Bytecode::CastU64 => Opcode::CastU64,
            Bytecode::CastU128 => Opcode::CastU128,
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
            Bytecode::Le => Opcode::Le,
            Bytecode::Lt => Opcode::Lt,
            Bytecode::Ge => Opcode::Ge,
            Bytecode::Gt => Opcode::Gt,
            Bytecode::Pack(_) => Opcode::Pack,
            Bytecode::Unpack(_) => Opcode::Unpack,
            Bytecode::MutBorrowLoc(_) => Opcode::MutBorrowLoc,
            Bytecode::ImmBorrowLoc(_) => Opcode::ImmBorrowLoc,
            Bytecode::ReadRef => Opcode::ReadRef,
            Bytecode::WriteRef => Opcode::WriteRef,
            Bytecode::FreezeRef => Opcode::FreezeRef,
            Bytecode::ImmBorrowField(_) => Opcode::ImmBorrowField,
            Bytecode::MutBorrowField(_) => Opcode::MutBorrowField,
            Bytecode::MoveFrom(_) => Opcode::MoveFrom,
            Bytecode::MoveTo(_) => Opcode::MoveTo,
            Bytecode::Exists(_) => Opcode::Exists,
            Bytecode::ImmBorrowGlobal(_) => Opcode::ImmBorrowGlobal,
            Bytecode::MutBorrowGlobal(_) => Opcode::MutBorrowGlobal,

            _ => unimplemented!(),
        }
    }
}
