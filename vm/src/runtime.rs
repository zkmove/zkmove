use crate::error::VmResult;
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

    pub fn execute_script(&self, script: Vec<u8>) -> VmResult<()> {
        Ok(())
    }
}
