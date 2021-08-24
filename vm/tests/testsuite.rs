use anyhow::Result;
use logger::prelude::*;
use movelang::{argument::ScriptArguments, compiler::compile_script};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use vm::runtime::Runtime;

fn parse_arguments(script_file: &Path) -> Result<ScriptArguments> {
    let file_str = script_file.to_str().expect("path is None.");

    let mut f = File::open(script_file)
        .map_err(|err| std::io::Error::new(err.kind(), format!("{}: {}", err, file_str)))?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;

    for line in buffer.lines().into_iter() {
        let s = line.split_whitespace().collect::<String>();
        if let Some(s) = s.strip_prefix("//!args:") {
            return s.parse::<ScriptArguments>();
        }
    }
    Ok(ScriptArguments::new(vec![]))
}

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    let script_file = path.to_str().expect("path is None.");
    let compiled_script = compile_script(script_file)?;

    let args = parse_arguments(path)?;
    debug!("script arguments {:?}", args);

    if let Some(script) = compiled_script {
        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;
        let runtime = Runtime::new();
        runtime.execute_script(script_bytes, args)?
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");
