use crate::vm_circuit::chips::bytecode::{
    _mod::Mod, add::Add, and::And, br_false::BrFalse, br_true::BrTrue, branch::Branch, call::Call,
    copy_loc::CopyLoc, div::Div, eq::Eq, ld_false::LdFalse, ld_true::LdTrue, ldu128::LdU128,
    ldu64::LdU64, ldu8::LdU8, move_loc::MoveLoc, mul::Mul, neq::Neq, not::Not, or::Or, pop::Pop,
    ret::Ret, st_loc::StLoc, sub::Sub, abort::Abort,
};
use crate::vm_circuit::chips::lookup_tables::{BytecodeLookup, RWLookup};
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
pub mod call;
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
pub mod abort;

pub trait BytecodeInterface<F: FieldExt> {
    fn configure(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        bytecode_lookups: &mut Vec<(BytecodeLookup<F>, Expression<F>)>,
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
    Call,
    Abort,
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
            Opcode::Call => Call::assign(region, offset, step, rw_table, cells)?,
            Opcode::Abort => Abort::assign(region, offset, step, rw_table, cells)?,
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
            _ => unimplemented!(),
        }
    }
}

pub fn convert_to_fields<F: FieldExt>(bytecode: Bytecode) -> (F, F) {
    match bytecode {
        Bytecode::LdU8(v) => (
            F::from_u128(Opcode::LdU8.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU64(v) => (
            F::from_u128(Opcode::LdU64.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::LdU128(v) => (
            F::from_u128(Opcode::LdU128.index() as u128),
            F::from_u128(v as u128),
        ),
        Bytecode::Pop => (F::from_u128(Opcode::Pop.index() as u128), F::zero()),
        Bytecode::Ret => (F::from_u128(Opcode::Ret.index() as u128), F::zero()),
        Bytecode::Add => (F::from_u128(Opcode::Add.index() as u128), F::zero()),
        Bytecode::Mul => (F::from_u128(Opcode::Mul.index() as u128), F::zero()),
        Bytecode::CopyLoc(local_index) => (
            F::from_u128(Opcode::CopyLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::Sub => (F::from_u128(Opcode::Sub.index() as u128), F::zero()),
        Bytecode::Div => (F::from_u128(Opcode::Div.index() as u128), F::zero()),
        Bytecode::Mod => (F::from_u128(Opcode::Mod.index() as u128), F::zero()),
        Bytecode::LdTrue => (F::from_u128(Opcode::LdTrue.index() as u128), F::zero()),
        Bytecode::LdFalse => (F::from_u128(Opcode::LdFalse.index() as u128), F::zero()),
        Bytecode::Eq => (F::from_u128(Opcode::Eq.index() as u128), F::zero()),
        Bytecode::Neq => (F::from_u128(Opcode::Neq.index() as u128), F::zero()),
        Bytecode::And => (F::from_u128(Opcode::And.index() as u128), F::zero()),
        Bytecode::Or => (F::from_u128(Opcode::Or.index() as u128), F::zero()),
        Bytecode::Not => (F::from_u128(Opcode::Not.index() as u128), F::zero()),
        Bytecode::MoveLoc(local_index) => (
            F::from_u128(Opcode::MoveLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::StLoc(local_index) => (
            F::from_u128(Opcode::StLoc.index() as u128),
            F::from_u128(local_index as u128),
        ),
        Bytecode::Branch(code_offset) => (
            F::from_u128(Opcode::Branch.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::BrTrue(code_offset) => (
            F::from_u128(Opcode::BrTrue.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::BrFalse(code_offset) => (
            F::from_u128(Opcode::BrFalse.index() as u128),
            F::from_u128(code_offset as u128),
        ),
        Bytecode::Call(func_handle_index) => (
            F::from_u128(Opcode::Call.index() as u128),
            F::from_u128(func_handle_index.0 as u128),
        ),
        Bytecode::Abort => (
            F::from_u128(Opcode::Abort.index() as u128),
            F::zero(),
        ),
        _ => unimplemented!("{:?}", bytecode),
    }
}
