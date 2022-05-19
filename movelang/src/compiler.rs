// Copyright (c) zkMove Authors

use anyhow::{bail, Result};
use move_binary_format::file_format::CompiledScript;
use move_binary_format::CompiledModule;
use move_compiler::compiled_unit::{CompiledUnit, NamedCompiledModule, NamedCompiledScript};
use move_compiler::shared::NumericalAddress;
use move_compiler::{self, Compiler, Flags};
use std::collections::BTreeMap;

pub fn compile_script(
    targets: Vec<String>,
) -> Result<(Option<CompiledScript>, Vec<CompiledModule>)> {
    let (_, compiled_units) =
        Compiler::from_files(targets, vec![], BTreeMap::<String, NumericalAddress>::new())
            .set_flags(Flags::empty().set_sources_shadow_deps(false))
            .build_and_report()?;

    let mut compiled_script = None;
    let mut modules = vec![];
    for c in compiled_units {
        match c.into_compiled_unit() {
            CompiledUnit::Script(NamedCompiledScript { script, .. }) => {
                if compiled_script.is_some() {
                    bail!("found more than one script.")
                }
                compiled_script = Some(script)
            }
            CompiledUnit::Module(NamedCompiledModule { module, .. }) => modules.push(module),
        }
    }

    Ok((compiled_script, modules))
}
