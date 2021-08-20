use logger::prelude::*;
use movelang::compiler::compile_script;
use std::path::Path;
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
                .unwrap_or_else(|_| panic!("vm test failed"));
        }
        None => debug!("Unable to find script in file {:?}", script_file),
    };
    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");
