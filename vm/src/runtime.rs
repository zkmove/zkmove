use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::interpreter::Interpreter;
use bellman::pairing::bn256::Bn256;
use crypto::constraint_system::DummyCS;
use logger::prelude::*;
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
        let mut cs = DummyCS::<Bn256>::new();
        let mut interp = Interpreter::new();

        let entry = self
            .loader
            .load_script(&script)
            .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))?;
        debug!("script entry {:?}", entry.name());

        interp.run_script(&mut cs, entry)
    }
}
