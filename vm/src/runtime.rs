use crate::error::{RuntimeError, StatusCode, VmResult};
use crate::frame::{Frame, Locals};
use crate::interpreter::Interpreter;
use bellman::pairing::bn256::Bn256;
use crypto::constraint_system::DummyCS;
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
        println!("script entry {:?}", entry.name());

        let locals = Locals::new();
        let mut frame = Frame::new(entry, locals);
        frame.execute(&mut cs, &mut interp)?;
        Ok(())
    }
}
