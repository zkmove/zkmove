// Copyright (c) zkMove Authors
pub mod frame;
pub mod globals;
pub mod interpreter;
pub mod locals;
pub mod native_functions;
pub mod runtime;
pub mod stack;
pub mod state;

pub mod loader;
pub mod natives;
#[cfg(test)]
mod tests;
