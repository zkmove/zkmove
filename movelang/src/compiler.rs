use anyhow::{bail, Result};
use move_binary_format::file_format::CompiledScript;
use move_binary_format::CompiledModule;
use move_lang::{self, compiled_unit::CompiledUnit, shared::Flags};

pub fn compile_script(targets: &[String]) -> Result<(Option<CompiledScript>, Vec<CompiledModule>)> {
    let (_, compiled_units) = move_lang::move_compile(
        targets,
        &[],
        None,
        Flags::empty().set_sources_shadow_deps(false),
    )?;

    let mut compiled_script = None;
    let mut modules = vec![];
    for c in compiled_units.expect("Unwrap CompiledUnit failed.") {
        match c {
            CompiledUnit::Script { script, .. } => {
                if compiled_script.is_some() {
                    bail!("found more than one script.")
                }
                compiled_script = Some(script)
            }
            CompiledUnit::Module { module, .. } => modules.push(module),
        }
    }

    Ok((compiled_script, modules))
}
