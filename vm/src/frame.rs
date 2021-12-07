// Copyright (c) zkMove Authors

use crate::circuit::EvaluationChip;
use crate::instructions::{ArithmeticInstructions, Instructions, LogicalInstructions};
use crate::interpreter::Interpreter;
use crate::stack::BlockStack;
use crate::value::Value;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::{arithmetic::FieldExt, circuit::Layouter};
use logger::prelude::*;
use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};
use move_vm_runtime::loader::Function;
use movelang::value::MoveValueType;
use std::{cell::RefCell, rc::Rc, sync::Arc};

#[derive(Clone)]
pub struct Locals<F: FieldExt>(Rc<RefCell<Vec<Value<F>>>>);

impl<F: FieldExt> Locals<F> {
    pub fn new(size: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![Value::Invalid; size])))
    }

    pub fn copy(&self, index: usize) -> VmResult<Value<F>> {
        let values = self.0.borrow();
        match values.get(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::CopyLocalError)),
            Some(v) => Ok(v.clone()),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn store(&mut self, index: usize, value: Value<F>) -> VmResult<()> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            // Todo: check ref count
            Some(_v) => {
                values[index] = value;
                Ok(())
            }
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn move_(&self, index: usize) -> VmResult<Value<F>> {
        let mut values = self.0.borrow_mut();
        match values.get_mut(index) {
            Some(Value::Invalid) => Err(RuntimeError::new(StatusCode::MoveLocalError)),
            Some(v) => Ok(std::mem::replace(v, Value::Invalid)),
            None => Err(RuntimeError::new(StatusCode::OutOfBounds)),
        }
    }

    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }
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

    pub fn locals(&mut self) -> &mut Locals<F> {
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
    block: Block<F>,
    is_running: bool, //which arm of conditional branch is running
}

#[derive(Clone, Debug)]
pub struct ConditionalBlock<F: FieldExt> {
    true_branch: Option<Branch<F>>,
    false_branch: Option<Branch<F>>,
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
            match (t_locals.0.borrow().get(i), f_locals.0.borrow().get(i)) {
                (Some(t), Some(f)) => {
                    if !t.equals(f) {
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

pub struct Frame<F: FieldExt> {
    current_block: ProgramBlock<F>,
    blocks: BlockStack<F>,
    function: Arc<Function>,
}

impl<F: FieldExt> Frame<F> {
    pub fn new(
        pc: u16,
        start: u16,
        end: Option<u16>,
        function: Arc<Function>,
        locals: Locals<F>,
    ) -> Self {
        let code = function.code();
        let func_body = ProgramBlock::new_block(
            pc,
            start,
            end,
            locals.clone(),
            code.to_vec(),
            Some(F::one()),
        );
        Frame {
            current_block: func_body,
            blocks: BlockStack::default(),
            function,
        }
    }

    pub fn current_block(&mut self) -> &mut ProgramBlock<F> {
        &mut self.current_block
    }

    pub fn func(&self) -> &Arc<Function> {
        &self.function
    }

    // todo: identify blocks through static analysis
    pub fn prepare_conditional_block(
        &mut self,
        pc: u16,
        condition: Option<F>,
    ) -> VmResult<ProgramBlock<F>> {
        let code = self.function.code();
        let not_condition = match condition {
            Some(v) => Some(F::one() - v),
            None => None,
        };
        let (_br_type, true_branch_start) = match &code[pc as usize] {
            Bytecode::BrTrue(offset) => (true, *offset),
            _ => {
                return Err(RuntimeError::new(StatusCode::ProgramBlockError)
                    .with_message("expect BrTrue or BrFalse".to_string()))
            }
        };
        match &code[(true_branch_start - 1) as usize] {
            Bytecode::Branch(offset) => {
                let true_branch_end = *offset - 1;
                match &code[(true_branch_end) as usize] {
                    Bytecode::Branch(offset) => {
                        let true_branch = Block::new(
                            true_branch_start,
                            true_branch_start,
                            Some(true_branch_end - 1), //ignore the branch instruction at the end
                            self.current_block.locals().clone(),
                            self.function.code().to_vec(),
                            condition,
                        );
                        let false_branch_start = true_branch_end + 1;
                        let false_branch_end = *offset - 1;
                        let false_branch = Block::new(
                            false_branch_start,
                            false_branch_start,
                            Some(false_branch_end),
                            self.current_block().locals().clone(),
                            self.function.code().to_vec(),
                            not_condition,
                        );
                        Ok(ProgramBlock::new_conditional_block(
                            Some(true_branch),
                            Some(false_branch),
                        ))
                    }
                    _ => {
                        let true_branch = Block::new(
                            true_branch_start,
                            true_branch_start,
                            Some(true_branch_end),
                            self.current_block.locals().clone(),
                            self.function.code().to_vec(),
                            condition,
                        );
                        Ok(ProgramBlock::new_conditional_block(Some(true_branch), None))
                    }
                }
            }
            Bytecode::Abort => {
                let false_branch_start = pc + 1;
                let false_branch_end = true_branch_start - 1;
                let false_branch = Block::new(
                    false_branch_start,
                    false_branch_start,
                    Some(false_branch_end),
                    self.current_block().locals().clone(),
                    self.function.code().to_vec(),
                    not_condition.clone(),
                );
                Ok(ProgramBlock::new_conditional_block(
                    None,
                    Some(false_branch),
                ))
            }
            _ => {
                return Err(RuntimeError::new(StatusCode::ProgramBlockError)
                    .with_message("Should not reach here".to_string()))
            }
        }
    }

    pub fn execute(
        &mut self,
        evaluation_chip: &EvaluationChip<F>,
        mut layouter: impl Layouter<F>,
        interp: &mut Interpreter<F>,
    ) -> VmResult<ExitStatus<F>> {
        loop {
            let status = self.current_block.execute(
                evaluation_chip,
                layouter.namespace(|| format!("into block in step#{}", interp.step)),
                interp,
            )?;
            match status {
                ExitStatus::Return => return Ok(ExitStatus::Return),
                ExitStatus::Call(index) => return Ok(ExitStatus::Call(index)),
                ExitStatus::ConditionalBranch(cb) => {
                    debug!("handle conditional branch");
                    let block = self.prepare_conditional_block(cb.pc, cb.condition)?;
                    debug!("{:?}", block);
                    self.blocks.push(self.current_block.clone())?;
                    self.current_block = block;
                }
                ExitStatus::BranchEnd(pc) => match &mut self.current_block {
                    ProgramBlock::ConditionalBlock(cb) => {
                        match (&mut cb.true_branch, &mut cb.false_branch) {
                            (Some(t_branch), Some(f_branch)) => {
                                if t_branch.is_running {
                                    debug_assert!(t_branch.block.end == Some(pc));
                                    debug!("switch conditional branch");
                                    t_branch.is_running = false;
                                    f_branch.is_running = true;
                                } else {
                                    debug_assert!(f_branch.is_running);
                                    debug_assert!(f_branch.block.end == Some(pc));
                                    debug!("merge the branch");
                                    let mut next_running = self.blocks.pop().ok_or_else(|| {
                                        RuntimeError::new(StatusCode::ShouldNotReachHere)
                                    })?;
                                    next_running.merge_locals(
                                        evaluation_chip,
                                        layouter.namespace(|| {
                                            format!("merge locals in step#{}", interp.step)
                                        }),
                                        &t_branch.block.locals,
                                        &f_branch.block.locals,
                                        t_branch.block.condition,
                                    )?;
                                    self.current_block = next_running;
                                    self.current_block.set_pc(pc + 1);
                                }
                            }
                            (Some(t_branch), None) => {
                                debug_assert!(t_branch.block.end == Some(pc));
                                debug!("merge the branch");
                                let mut next_running = self.blocks.pop().ok_or_else(|| {
                                    RuntimeError::new(StatusCode::ShouldNotReachHere)
                                })?;
                                next_running.set_locals(t_branch.block.locals.clone());
                                self.current_block = next_running;
                                self.current_block.set_pc(pc + 1);
                            }
                            (None, Some(f_branch)) => {
                                debug_assert!(f_branch.block.end == Some(pc));
                                debug!("merge the branch");
                                let mut next_running = self.blocks.pop().ok_or_else(|| {
                                    RuntimeError::new(StatusCode::ShouldNotReachHere)
                                })?;
                                next_running.set_locals(f_branch.block.locals.clone());
                                self.current_block = next_running;
                                self.current_block.set_pc(pc + 1);
                            }
                            _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
                        }
                    }
                    _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
                },
                ExitStatus::Abort(pc, error_code) => match &mut self.current_block {
                    ProgramBlock::ConditionalBlock(cb) => {
                        match (&mut cb.true_branch, &mut cb.false_branch) {
                            (None, Some(f_branch)) => {
                                debug_assert!(f_branch.block.end == Some(pc));
                                debug!("handle Abort");
                                let cond = f_branch.block.condition;
                                self.current_block = self.blocks.pop().ok_or_else(|| {
                                    RuntimeError::new(StatusCode::ShouldNotReachHere)
                                })?;
                                self.current_block.set_pc(pc + 1);

                                // todo: error handle
                                if cond == Some(F::one()) {
                                    return Err(RuntimeError::new(StatusCode::MoveAbort)
                                        .with_message(format!(
                                            "Move bytecode {} aborted with error code {}",
                                            self.function.pretty_string(),
                                            error_code
                                        )));
                                }
                            }
                            _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
                        }
                    }
                    _ => return Err(RuntimeError::new(StatusCode::ShouldNotReachHere)),
                },
            }
        }
    }

    pub fn print_frame(&self) {
        // print bytecode of the current function
        println!("Bytecode of function {:?}:", self.function.name());
        for (i, instruction) in self.function.code().iter().enumerate() {
            println!("#{}, {:?}", i, instruction);
        }
    }
}

pub struct ConditionalBranch<F: FieldExt> {
    pc: u16,
    condition: Option<F>,
}

pub enum ExitStatus<F: FieldExt> {
    Return,
    Call(FunctionHandleIndex),
    ConditionalBranch(ConditionalBranch<F>),
    BranchEnd(u16 /* pc */),
    Abort(u16 /* pc */, u128 /* error code */),
}
