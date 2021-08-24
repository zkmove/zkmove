use anyhow::Result;
use logger::prelude::*;
use movelang::{argument::ScriptArguments, compiler::compile_script};
use std::fs::File;
use std::io::{Error, Read};
use std::path::Path;
use vm::error::StatusCode;
use vm::runtime::Runtime;

fn parse_arguments(input: &str) -> Result<ScriptArguments> {
    for line in input.lines().into_iter() {
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

    let mut f = File::open(script_file)
        .map_err(|err| Error::new(err.kind(), format!("{}: {}", err, script_file)))?;
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;
    let args = parse_arguments(&buffer)?;
    debug!("script arguments {:?}", args);

    match compiled_script {
        Some(script) => {
            let mut script_bytes = vec![];
            script.serialize(&mut script_bytes)?;
            let runtime = Runtime::new();
            runtime
                .execute_script(script_bytes, args)
                .unwrap_or_else(|e| match e.status_code() {
                    StatusCode::MoveAbort => {
                        info!(
                            "{}",
                            e.message()
                                .unwrap_or("move abort with no message".to_string())
                        )
                    }
                    _ => {
                        panic!("test failed with unexpected error");
                    }
                });
        }
        None => debug!("Unable to find script in file {:?}", script_file),
    };
    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");
