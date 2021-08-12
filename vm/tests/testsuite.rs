use std::path::Path;

fn vm_test(_path: &Path) -> datatest_stable::Result<()> {
    Ok(())
}

datatest_stable::harness!(vm_test, "tests/testsuite", r".*\.move");