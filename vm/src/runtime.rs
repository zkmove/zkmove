// Copyright (c) zkMove Authors

use movelang::loader::MoveLoader;

pub struct Runtime {
    loader: MoveLoader,
}

impl Runtime {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new(),
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
