// Copyright (c) zkMove Authors

use crate::circuit::EvaluationChip;
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
use crate::interpreter::Interpreter;
use crate::locals::Locals;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::{arithmetic::FieldExt, circuit::Layouter};
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use movelang::value::MoveValueType;

pub struct ConditionalBranch<F: FieldExt> {
    pub pc: u16,
    pub condition: Option<F>,
}

pub enum ExitStatus<F: FieldExt> {
    Return,
    Call(FunctionHandleIndex),
    ConditionalBranch(ConditionalBranch<F>),
    BranchEnd(u16 /* pc */),
    Abort(u16 /* pc */, u128 /* error code */),
}

// Block can be a function body, or an arm of conditional branch
#[derive(Clone)]
pub struct Block<F: FieldExt> {
    pc: u16,
    start: u16,
    end: Option<u16>,
    locals: Locals<F>,
    code: Vec<Bytecode>,
    condition: Option<F>,
}

impl<F: FieldExt> Block<F> {
    pub fn new(
        pc: u16,
        start: u16,
        end: Option<u16>,
        locals: Locals<F>,
        code: Vec<Bytecode>,
        condition: Option<F>,
    ) -> Self {
        Block {
            pc,
            start,
            end,
            locals,
            code,
            condition,
        }
    }

    pub fn pc(&self) -> u16 {
        self.pc
    }

    pub fn add_pc(&mut self) {
        self.pc += 1;
    }

    pub fn set_pc(&mut self, next: u16) {
        self.pc = next;
    }

    pub fn end(&self) -> Option<u16> {
        self.end
    }

    pub fn locals(&self) -> &Locals<F> {
        &self.locals
    }

    pub fn locals_mut(&mut self) -> &mut Locals<F> {
        &mut self.locals
    }

    pub fn condition(&self) -> Option<F> {
        self.condition
    }

    pub fn execute(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        interp: &mut Interpreter<F>,
    ) -> VmResult<ExitStatus<F>> {
        macro_rules! load_constant {
            ($constant:expr, $ty:expr) => {{
                let value = evaluation_chip
                    .load_constant(
                        layouter.namespace(|| format!("load constant in step#{}", interp.step)),
                        $constant,
                        $ty,
                    )
                    .map_err(|e| {
                        error!("load constant failed: {:?}", e);
                        RuntimeError::new(StatusCode::SynthesisError)
                    })?;
                interp.stack.push(value)
            }};
        }

        let code = self.code.as_slice();
        loop {
            for instruction in &code[self.pc as usize..] {
                debug!(
                    "step #{}, pc #{}, instruction {:?}",
                    interp.step, self.pc, instruction
                );
                interp.step += 1;

                match instruction {
                    Bytecode::LdU8(v) => {
                        let constant = F::from_u64(*v as u64);
                        load_constant!(constant, MoveValueType::U8)
                    }
                    Bytecode::LdU64(v) => {
                        let constant = F::from_u64(*v);
                        load_constant!(constant, MoveValueType::U64)
                    }
                    Bytecode::LdU128(v) => {
                        let constant = F::from_u128(*v);
                        load_constant!(constant, MoveValueType::U128)
                    }
                    Bytecode::Pop => {
                        interp.stack.pop()?;
                        Ok(())
                    }
                    Bytecode::Add => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .add(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                self.condition(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    Bytecode::Sub => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .sub(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                self.condition(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    Bytecode::Mul => {
                        let b = interp.stack.pop()?;
                        let a = interp.stack.pop()?;
                        let c = evaluation_chip
                            .mul(
                                layouter.namespace(|| format!("step#{}", interp.step)),
                                a,
                                b,
                                self.condition(),
                            )
                            .map_err(|e| {
                                error!("step#{} failed: {:?}", interp.step, e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    // Bytecode::Div => interp.binary_op(cs, r1cs::div),
                    // Bytecode::Mod => interp.binary_op(cs, r1cs::mod_),
                    Bytecode::Ret => return Ok(ExitStatus::Return),
                    Bytecode::Call(index) => return Ok(ExitStatus::Call(*index)),
                    Bytecode::CopyLoc(v) => interp.stack.push(self.locals.copy(*v as usize)?),
                    Bytecode::StLoc(v) => self.locals.store(*v as usize, interp.stack.pop()?),
                    Bytecode::MoveLoc(v) => interp.stack.push(self.locals.move_(*v as usize)?),
                    Bytecode::LdTrue => {
                        let constant = F::one();
                        load_constant!(constant, MoveValueType::Bool)
                    }
                    Bytecode::LdFalse => {
                        let constant = F::zero();
                        load_constant!(constant, MoveValueType::Bool)
                    }
                    Bytecode::BrTrue(_offset) => {
                        let cond = interp.stack.pop()?.value();
                        return Ok(ExitStatus::ConditionalBranch(ConditionalBranch {
                            pc: self.pc,
                            condition: cond,
                        }));
                    }
                    Bytecode::BrFalse(_offset) => {
                        let cond = interp.stack.pop()?.value();
                        return Ok(ExitStatus::ConditionalBranch(ConditionalBranch {
                            pc: self.pc,
                            condition: cond,
                        }));
                    }
                    Bytecode::Branch(offset) => {
                        self.pc = *offset;
                        break;
                    }
                    Bytecode::Abort => {
                        let value =
                            interp.stack.pop()?.value().ok_or_else(|| {
                                RuntimeError::new(StatusCode::ValueConversionError)
                            })?;
                        let error_code = value.get_lower_128(); // fixme should cast to u64?
                        return Ok(ExitStatus::Abort(self.pc, error_code));
                    }
                    Bytecode::Eq => {
                        let a = interp.stack.pop()?;
                        let b = interp.stack.pop()?;
                        let c = evaluation_chip
                            .eq(
                                layouter.namespace(|| format!("eq op in step#{}", interp.step)),
                                a,
                                b,
                                self.condition(),
                            )
                            .map_err(|e| {
                                error!("eq op failed: {:?}", e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        interp.stack.push(c)
                    }
                    // Bytecode::Neq => interp.binary_op(cs, r1cs::neq),
                    // Bytecode::And => interp.binary_op(cs, r1cs::and),
                    // Bytecode::Or => interp.binary_op(cs, r1cs::or),
                    // Bytecode::Not => interp.unary_op(cs, r1cs::not),
                    _ => unreachable!(),
                }?;

                if Some(self.pc) == self.end {
                    debug!("reach BranchEnd at pc {}", self.pc);
                    return Ok(ExitStatus::BranchEnd(self.pc));
                }
                self.pc += 1;
            }
        }
    }
}

impl<F: FieldExt> std::fmt::Debug for Block<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {{ pc {}, start {}, end {:?}, condition {:?} }}",
            self.pc, self.start, self.end, self.condition
        )
    }
}

#[derive(Clone, Debug)]
pub struct Branch<F: FieldExt> {
    pub block: Block<F>,
    pub is_running: bool, //which arm of conditional branch is running
}

#[derive(Clone, Debug)]
pub struct ConditionalBlock<F: FieldExt> {
    pub true_branch: Option<Branch<F>>,
    pub false_branch: Option<Branch<F>>,
}

impl<F: FieldExt> ConditionalBlock<F> {
    pub fn new(true_branch: Option<Block<F>>, false_branch: Option<Block<F>>) -> Self {
        let (true_branch, false_branch) = match (true_branch, false_branch) {
            (Some(true_bl), Some(false_bl)) => (
                Some(Branch {
                    block: true_bl,
                    is_running: true,
                }),
                Some(Branch {
                    block: false_bl,
                    is_running: false,
                }),
            ),
            (Some(true_bl), None) => (
                Some(Branch {
                    block: true_bl,
                    is_running: true,
                }),
                None,
            ),
            (None, Some(false_bl)) => (
                None,
                Some(Branch {
                    block: false_bl,
                    is_running: true,
                }),
            ),
            _ => (None, None),
        };
        ConditionalBlock {
            true_branch,
            false_branch,
        }
    }

    pub fn current_running(&mut self) -> Option<&mut Block<F>> {
        let mut current = None;
        if let Some(true_br) = &mut self.true_branch {
            if true_br.is_running {
                current = Some(&mut true_br.block);
            }
        }
        if let Some(false_br) = &mut self.false_branch {
            if false_br.is_running {
                current = Some(&mut false_br.block);
            }
        }
        current
    }

    pub fn execute(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        interp: &mut Interpreter<F>,
    ) -> VmResult<ExitStatus<F>> {
        let current = self.current_running().unwrap(); //fixme
        current.execute(
            evaluation_chip,
            layouter.namespace(|| format!("into block in step#{}", interp.step)),
            interp,
        )
    }
}

#[derive(Clone, Debug)]
pub enum ProgramBlock<F: FieldExt> {
    Block(Block<F>),
    ConditionalBlock(ConditionalBlock<F>),
}

impl<F: FieldExt> ProgramBlock<F> {
    pub fn new_block(
        pc: u16,
        start: u16,
        end: Option<u16>,
        locals: Locals<F>,
        code: Vec<Bytecode>,
        condition: Option<F>,
    ) -> Self {
        Self::Block(Block::new(pc, start, end, locals, code, condition))
    }

    pub fn new_conditional_block(
        true_branch: Option<Block<F>>,
        false_branch: Option<Block<F>>,
    ) -> Self {
        Self::ConditionalBlock(ConditionalBlock::new(true_branch, false_branch))
    }

    pub fn pc(&self) -> u16 {
        match self {
            Self::Block(block) => block.pc,
            Self::ConditionalBlock(_conditional) => unimplemented!(),
        }
    }

    pub fn add_pc(&mut self) {
        match self {
            Self::Block(block) => block.pc += 1,
            Self::ConditionalBlock(_conditional) => unimplemented!(),
        }
    }

    pub fn set_pc(&mut self, next: u16) {
        match self {
            Self::Block(block) => block.pc = next,
            Self::ConditionalBlock(_conditional) => unimplemented!(),
        }
    }

    pub fn locals(&mut self) -> &mut Locals<F> {
        match self {
            Self::Block(block) => &mut block.locals,
            Self::ConditionalBlock(_conditional) => unimplemented!(),
        }
    }

    pub fn set_locals(&mut self, locals: Locals<F>) {
        match self {
            Self::Block(block) => block.locals = locals,
            Self::ConditionalBlock(_conditional) => unimplemented!(),
        }
    }

    pub fn merge_locals(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        t_locals: &Locals<F>,
        f_locals: &Locals<F>,
        condition: Option<F>,
    ) -> VmResult<()> {
        debug_assert!(t_locals.len() == f_locals.len());
        for i in 0..t_locals.len() {
            match (t_locals.get(i), f_locals.get(i)) {
                (Some(t), Some(f)) => {
                    if !t.equals(&f) {
                        let local = evaluation_chip
                            .conditional_select(
                                layouter.namespace(|| format!("merge_locals {}", i)),
                                t.clone(),
                                f.clone(),
                                condition,
                            )
                            .map_err(|e| {
                                error!("merge locals failed: {:?}", e);
                                RuntimeError::new(StatusCode::SynthesisError)
                            })?;
                        self.locals().store(i, local)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn execute(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        interp: &mut Interpreter<F>,
    ) -> VmResult<ExitStatus<F>> {
        match self {
            Self::Block(block) => block.execute(
                evaluation_chip,
                layouter.namespace(|| format!("into block in step#{}", interp.step)),
                interp,
            ),
            Self::ConditionalBlock(conditional) => conditional.execute(
                evaluation_chip,
                layouter.namespace(|| format!("into conditional block in step#{}", interp.step)),
                interp,
            ),
        }
    }
}
