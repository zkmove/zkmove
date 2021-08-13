use std::path::Path;
use movelang::compiler::compile_script;
use log::debug;

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    let script_file = path.to_str().expect("path is None.");
    let compiled_script =  compile_script(script_file)?;
    let mut bytecode= None;
    match compiled_script {
        Some(script) => {
            let mut script_bytes = vec![];
            script.serialize(&mut script_bytes)?;
            bytecode = Some(script_bytes);
        }
        None => debug!("Unable to find script in file {:?}", script_file),
    };
    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");
