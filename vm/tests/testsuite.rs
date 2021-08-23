use logger::prelude::*;
use movelang::compiler::compile_script;
use std::path::Path;
use vm::error::StatusCode;
use vm::runtime::Runtime;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    let script_file = path.to_str().expect("path is None.");
    let compiled_script = compile_script(script_file)?;
    let runtime = Runtime::new();

    match compiled_script {
        Some(script) => {
            let mut script_bytes = vec![];
            script.serialize(&mut script_bytes)?;
            runtime
                .execute_script(script_bytes)
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
