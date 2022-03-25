use crate::vm_circuit::chips::step_chip::StepChipCells;
use crate::vm_circuit::chips::utilities::Expr;
use crate::vm_circuit::circuit_inputs::{ExecutionStep, RWLookUpTable, RW};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Error, Expression};
use move_binary_format::file_format::Bytecode;
use std::marker::PhantomData;

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
}
// todo: we need a more secure way to get the number of Opcode members
pub const NUMBER_OF_BYTECODE_MEMBERS: usize = Opcode::CopyLoc as usize + 1;

impl Opcode {
    pub fn index(&self) -> usize {
        *self as usize
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
            _ => unimplemented!(),
        }
    }
}

pub struct BinaryOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BinaryOp<F> {
    pub fn constrain_binary_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            - 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 3.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond * gc_expr),
        ]);
    }

    pub fn lookup_binary_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_b.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_pop(
                cells.gc.expression.clone() + 1.expr(),
                cells.stack_size.expression.clone() - 1.expr(),
                cells.value_a.expression.clone(),
            ),
            cond.clone(),
        ));
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone() + 2.expr(),
                cells.stack_size.expression.clone() - 2.expr(),
                cells.value_c.expression.clone(),
            ),
            cond,
        ));
    }

    pub fn assign_binary_op(
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecutionStep,
        rw_table: &RWLookUpTable<F>,
        cells: &StepChipCells<F>,
    ) -> Result<(), Error> {
        let op = rw_table.0.get(step.gc).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_b.assign(region, offset, op.value().value())?;

        let op = rw_table.0.get(step.gc + 1).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::READ);
        cells.value_a.assign(region, offset, op.value().value())?;

        let op = rw_table.0.get(step.gc + 2).ok_or(Error::Synthesis)?;
        debug_assert!(op.rw() == RW::WRITE);
        cells.value_c.assign(region, offset, op.value().value())?;

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RWTarget {
    Stack = 0,
    Locals,
}

pub struct LoadOp<F: FieldExt> {
    _marker: PhantomData<F>,
}

impl<F: FieldExt> LoadOp<F> {
    pub fn constrain_ld_op(
        cells: &StepChipCells<F>,
        constraints: &mut Vec<(&str, Expression<F>)>,
        cond: Expression<F>,
    ) {
        let pc_expr = cells.pc.expression.clone() - cells.next_pc.expression.clone() + 1.expr();
        let stack_size_expr = cells.stack_size.expression.clone()
            - cells.next_stack_size.expression.clone()
            + 1.expr();
        let call_index_expr =
            cells.call_index.expression.clone() - cells.next_call_index.expression.clone();
        let gc_expr = cells.gc.expression.clone() - cells.next_gc.expression.clone() + 1.expr();
        constraints.append(&mut vec![
            ("pc", cond.clone() * pc_expr),
            ("stack size", cond.clone() * stack_size_expr),
            ("call index", cond.clone() * call_index_expr),
            ("gc", cond * gc_expr),
        ]);
    }

    pub fn lookup_ld_op(
        cells: &StepChipCells<F>,
        rw_lookups: &mut Vec<(RWLookup<F>, Expression<F>)>,
        cond: Expression<F>,
    ) {
        rw_lookups.push((
            RWLookup::stack_push(
                cells.gc.expression.clone(),
                cells.stack_size.expression.clone(),
                cells.value_a.expression.clone(),
            ),
            cond,
        ));
    }
}

pub struct RWLookup<F: FieldExt> {
    pub gc: Expression<F>,         // global counter
    pub rw_target: Expression<F>,  // RWTarget
    pub rw: Expression<F>,         // read or write
    pub call_index: Expression<F>, // always zero for stack op
    pub address: Expression<F>,    // locals index, or stack address
    pub value: Expression<F>,
}

impl<F: FieldExt> RWLookup<F> {
    pub fn stack_push(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::WRITE as u64).expr(),
            call_index: 0.expr(),
            address: stack_size,
            value,
        }
    }

    pub fn stack_pop(
        gc: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> RWLookup<F> {
        RWLookup {
            gc,
            rw_target: (RWTarget::Stack as u64).expr(),
            rw: (RW::READ as u64).expr(),
            call_index: 0.expr(),
            address: stack_size - 1.expr(),
            value,
        }
    }

    pub fn locals_copy(
        gc: Expression<F>,
        call_index: Expression<F>,
        locals_index: Expression<F>,
        stack_size: Expression<F>,
        value: Expression<F>,
    ) -> (RWLookup<F>, RWLookup<F>) {
        (
            RWLookup {
                gc: gc.clone(),
                rw_target: (RWTarget::Locals as u64).expr(),
                rw: (RW::READ as u64).expr(),
                call_index,
                address: locals_index,
                value: value.clone(),
            },
            RWLookup {
                gc: gc + 1.expr(),
                rw_target: (RWTarget::Stack as u64).expr(),
                rw: (RW::WRITE as u64).expr(),
                call_index: 0.expr(),
                address: stack_size,
                value,
            },
        )
    }
}
