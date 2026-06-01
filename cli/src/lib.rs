// Copyright (c) zkMove Authors

use anyhow::{Context, Result};
use clap::ValueEnum;
use log::debug;
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId,
};
use move_package::compilation::compiled_package::{CompiledPackage, OnDiskCompiledPackage};
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use serde::Serialize;
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};
use toml::Value;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::{EntryInfo, ModuleIdMapping};

pub mod aptos_cmds;
pub mod poseidon_cmds;
pub mod sui_cmds;
pub mod vm_cmds;

/// Common code used by multiple command modules.

#[derive(Serialize)]
pub struct ArgWithNameAndTypeJSON {
    pub name: String,
    pub r#type: String,
    pub value: serde_json::Value,
}

#[derive(Serialize)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl fmt::Display for HexEncodedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KZGVariant {
    GWC,
    SHPLONK,
}

pub(crate) fn load_package(rooted_path: &Path) -> Result<CompiledPackage> {
    let manifest_path = rooted_path.join(SourcePackageLayout::Manifest.path());
    let manifest_string = std::fs::read_to_string(&manifest_path)?;
    let toml_manifest =
        move_package::source_package::manifest_parser::parse_move_manifest_string(manifest_string)?;
    let manifest =
        move_package::source_package::manifest_parser::parse_source_manifest(toml_manifest)?;

    let package_name = manifest.package.name.to_string();
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(&package_name);

    let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
    package.into_compiled_package()
}

pub(crate) fn get_circuit_config_args_from_move_toml(
    toml_path: &Path,
    circuit_name: Option<&str>,
) -> Result<CircuitConfigArgs> {
    let content = std::fs::read_to_string(toml_path).context("Failed to read Move.toml")?;

    let parsed: Value = content.parse().context("Failed to parse Move.toml")?;

    let circuit_table = match circuit_name {
        Some(name) => parsed
            .get("circuit")
            .and_then(|c| c.get(name))
            .with_context(|| format!("[circuit.{}] not found", name))?,

        None => parsed
            .get("circuit")
            .context("[circuit] section not found")?,
    };

    let table = circuit_table
        .as_table()
        .context("circuit section is not a table")?;

    let max_execution_rows = table
        .get("max_execution_rows")
        .and_then(|v| v.as_integer())
        .map(|v| v as usize);

    let max_poseidon_rows = table
        .get("max_poseidon_rows")
        .and_then(|v| v.as_integer())
        .map(|v| v as usize)
        .unwrap_or(0);

    Ok(CircuitConfigArgs {
        max_execution_rows,
        max_poseidon_rows,
    })
}

pub(crate) fn get_entry_info_from_move_toml(
    toml_path: &Path,
    circuit_name: Option<&str>,
) -> Result<EntryInfo> {
    let content = std::fs::read_to_string(toml_path).context("Failed to read Move.toml")?;

    let parsed: Value = content.parse().context("Failed to parse Move.toml")?;

    let circuit_table = match circuit_name {
        Some(name) => parsed
            .get("circuit")
            .and_then(|c| c.get(name))
            .with_context(|| format!("[circuit.{}] not found", name))?,

        None => parsed
            .get("circuit")
            .context("[circuit] section not found")?,
    };

    let entry = circuit_table
        .get("entry")
        .context("'entry' field not found in circuit section")?;

    let module_id_str = entry
        .get("module_id")
        .and_then(|v| v.as_str())
        .context("module_id is missing or invalid")?;

    let function_name = entry
        .get("function_name")
        .and_then(|v| v.as_str())
        .context("function_name is missing or invalid")?;

    let module_id = parse_module_id(module_id_str)?;

    let package_root = find_package_root(toml_path)?;
    let package = load_package(&package_root)?;
    let module_id_mapping = ModuleIdMapping::construct(&module_id, &package);

    Ok(EntryInfo::new(
        &package,
        &module_id,
        function_name,
        &module_id_mapping,
    ))
}

fn find_package_root(path: &Path) -> Result<PathBuf> {
    SourcePackageLayout::try_find_root(&path.canonicalize()?)
        .context("Failed to find root path for the package")
}

fn parse_module_id(module_id_str: &str) -> Result<ModuleId> {
    let parts: Vec<&str> = module_id_str.split("::").collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid module_id format: {}",
            module_id_str
        ));
    }
    let address = AccountAddress::from_str(parts[0])?;
    let name = Identifier::new(parts[1])?;
    Ok(ModuleId::new(address, name))
}

pub(crate) fn save_to_file<P: AsRef<Path>, D: AsRef<[u8]>>(
    dir: P,
    file_name: &str,
    data: D,
) -> Result<()> {
    let file_path = dir.as_ref().join(file_name);
    std::fs::write(&file_path, data)?;
    debug!("File saved to {:?}", file_path.display());
    Ok(())
}
