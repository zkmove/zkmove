use anyhow::{bail, Result};
use logger::prelude::*;
use move_binary_format::file_format::CompiledScript;
use move_lang::{self, compiled_unit::CompiledUnit, shared::Flags};

pub fn compile_script(script_file: &str) -> Result<Option<CompiledScript>> {
    let (_, compiled_units) = move_lang::move_compile(
        &[script_file.to_string()],
        &[],
        None,
        Flags::empty().set_sources_shadow_deps(false),
    )?;

    let mut compiled_script = None;
    for c in compiled_units.expect("Unwrap CompiledUnit failed.") {
        match c {
            CompiledUnit::Script { script, .. } => {
                if compiled_script.is_some() {
                    bail!("found more than one script.")
                }
                compiled_script = Some(script)
            }
            CompiledUnit::Module { .. } => {
                debug!("module is compiled.")
            }
        }
    }

    Ok(compiled_script)
}
