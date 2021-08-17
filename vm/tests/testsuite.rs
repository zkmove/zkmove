use log::debug;
use movelang::compiler::compile_script;
use std::path::Path;
use vm::runtime::Runtime;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    let script_file = path.to_str().expect("path is None.");
    let compiled_script = compile_script(script_file)?;

    let runtime = Runtime::new();

    match compiled_script {
        Some(script) => {
            let mut script_bytes = vec![];
            script.serialize(&mut script_bytes)?;
            runtime.execute_script(script_bytes);
            println!("just for test");
        }
        None => debug!("Unable to find script in file {:?}", script_file),
    };
    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");
