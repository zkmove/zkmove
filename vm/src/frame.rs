// Copyright (c) zkMove Authors

use crate::evaluation_chip::EvaluationChip;
use crate::interpreter::Interpreter;
use crate::locals::Locals;
use crate::program_block::{Block, ExitStatus, ProgramBlock};
use crate::stack::BlockStack;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::{arithmetic::FieldExt, circuit::Layouter};
use logger::prelude::*;
use move_binary_format::file_format::Bytecode;
use move_vm_runtime::loader::Function;
use std::sync::Arc;

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
        let func_body =
            ProgramBlock::new_block(pc, start, end, locals, code.to_vec(), Some(F::one()));
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

    // todo: identify blocks through static analysis?
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
                    not_condition,
                );
                Ok(ProgramBlock::new_conditional_block(
                    None,
                    Some(false_branch),
                ))
            }
            _ => Err(RuntimeError::new(StatusCode::ProgramBlockError)
                .with_message("Should not reach here".to_string())),
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
                                    debug_assert!(t_branch.block.end() == Some(pc));
                                    debug!("switch conditional branch");
                                    t_branch.is_running = false;
                                    f_branch.is_running = true;
                                } else {
                                    debug_assert!(f_branch.is_running);
                                    debug_assert!(f_branch.block.end() == Some(pc));
                                    debug!("merge the branch");
                                    let mut next_running = self.blocks.pop().ok_or_else(|| {
                                        RuntimeError::new(StatusCode::ShouldNotReachHere)
                                    })?;
                                    next_running.merge_locals(
                                        evaluation_chip,
                                        layouter.namespace(|| {
                                            format!("merge locals in step#{}", interp.step)
                                        }),
                                        &t_branch.block.locals(),
                                        &f_branch.block.locals(),
                                        t_branch.block.condition(),
                                    )?;
                                    self.current_block = next_running;
                                    self.current_block.set_pc(pc + 1);
                                }
                            }
                            (Some(t_branch), None) => {
                                debug_assert!(t_branch.block.end() == Some(pc));
                                debug!("merge the branch");
                                let mut next_running = self.blocks.pop().ok_or_else(|| {
                                    RuntimeError::new(StatusCode::ShouldNotReachHere)
                                })?;
                                next_running.set_locals(t_branch.block.locals().clone());
                                self.current_block = next_running;
                                self.current_block.set_pc(pc + 1);
                            }
                            (None, Some(f_branch)) => {
                                debug_assert!(f_branch.block.end() == Some(pc));
                                debug!("merge the branch");
                                let mut next_running = self.blocks.pop().ok_or_else(|| {
                                    RuntimeError::new(StatusCode::ShouldNotReachHere)
                                })?;
                                next_running.set_locals(f_branch.block.locals().clone());
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
                                debug_assert!(f_branch.block.end() == Some(pc));
                                debug!("handle Abort");
                                let cond = f_branch.block.condition();
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
