// Copyright (c) zkMove Authors

use crate::api::circuit::build_empty_circuit_and_fit_params;
use crate::api::context::ZkMoveContext;
use crate::common::{
    get_circuit_config_args_from_move_toml, get_entry_info_from_move_toml, load_package,
    read_params, save_to_file,
};
use anyhow::Result;
use clap::{value_parser, Parser};
use halo2::proofs::setup_circuit;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use log::info;
use move_core_types::language_storage::ModuleId;
use move_package::compilation::compiled_package::CompiledPackage;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use vm_circuit::{CircuitConfigArgs, VmCircuit};
use witness::static_info::EntryInfo;

#[derive(Parser)]
#[command(about = "Generate app-developer setup artifacts for SDK initialization")]
pub struct SetupCommand {
    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

    #[arg(
        long = "circuit-name",
        short = 'c',
        help = "Name of the circuit section in Move.toml (e.g. fibonacci for [circuit.fibonacci]). If omitted, uses the plain [circuit] section in Move.toml."
    )]
    circuit_name: Option<String>,

    #[arg(long, help = "Params file used for KZG setup")]
    params_path: PathBuf,

    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g. 0 1 3)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save setup artifacts (default: <package-path>/setup)"
    )]
    output_dir: Option<PathBuf>,
}

impl SetupCommand {
    pub fn run(&self) -> Result<()> {
        let manifest_path = self.package_path.join("Move.toml");
        let circuit_name = self.circuit_name.as_deref();
        let package = load_package(&self.package_path)?;
        let entry_info = get_entry_info_from_move_toml(&manifest_path, circuit_name)?;
        let config = get_circuit_config_args_from_move_toml(&manifest_path, circuit_name)?;
        let params = read_params(&self.params_path)?;

        let output = build_setup_output(
            package,
            entry_info,
            config,
            params,
            self.pubs_indices.clone(),
        )?;

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| self.package_path.join("setup"));
        std::fs::create_dir_all(&output_dir)?;

        let metadata = serde_json::to_string_pretty(&output.metadata)?;
        save_to_file(&output_dir, "metadata.json", metadata)?;
        save_to_file(
            &output_dir,
            &output.metadata.params_file,
            output.params_bytes,
        )?;
        save_to_file(&output_dir, &output.metadata.pk_file, output.pk_bytes)?;
        save_to_file(&output_dir, &output.metadata.vk_file, output.vk_bytes)?;

        info!(
            "Setup artifacts saved to {} (k = {})",
            output_dir.display(),
            output.context.k
        );
        Ok(())
    }
}

/// JSON metadata emitted next to binary setup artifacts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SetupMetadata {
    pub(crate) k: u32,
    pub(crate) pubs_indices: Vec<usize>,
    pub(crate) entry_module_id: String,
    pub(crate) entry_function_index: u16,
    pub(crate) entry_num_args: u8,
    pub(crate) params_file: String,
    pub(crate) pk_file: String,
    pub(crate) vk_file: String,
    pub(crate) serde_format: String,
}

/// Command-layer setup output used by setup/prove/verify CLI workflows.
pub(crate) struct SetupOutput {
    pub(crate) context: ZkMoveContext,
    pub(crate) metadata: SetupMetadata,
    pub(crate) params_bytes: Vec<u8>,
    pub(crate) pk_bytes: Vec<u8>,
    pub(crate) vk_bytes: Vec<u8>,
}

pub(crate) fn build_setup_output(
    package: CompiledPackage,
    entry_info: EntryInfo,
    config: CircuitConfigArgs,
    mut params: ParamsKZG<Bn256>,
    pubs_indices: Vec<usize>,
) -> Result<SetupOutput> {
    VmCircuit::<Fr>::validate_setup_inputs(&package, &entry_info, &pubs_indices, &config)
        .map_err(anyhow::Error::msg)?;

    let (circuit, _circuit_guard, k) = build_empty_circuit_and_fit_params(
        &package,
        entry_info.clone(),
        config.clone(),
        &pubs_indices,
        &mut params,
    )?;

    let (vk, pk) = setup_circuit(&*circuit, &params)
        .map_err(|e| anyhow::anyhow!("setup circuit failed: {:?}", e))?;

    let metadata = SetupMetadata {
        k,
        pubs_indices: pubs_indices.clone(),
        entry_module_id: module_id_to_string(&entry_info.module_id),
        entry_function_index: entry_info.function_index,
        entry_num_args: entry_info.num_args,
        params_file: "params.bin".to_string(),
        pk_file: "pk.bin".to_string(),
        vk_file: "vk.bin".to_string(),
        serde_format: "raw-bytes".to_string(),
    };

    let context =
        ZkMoveContext::from_parts(package, entry_info, config, params, pk, vk, k, pubs_indices);

    let params_bytes = context.params_bytes()?;
    let pk_bytes = context.pk_bytes()?;
    let vk_bytes = context.vk_bytes();

    Ok(SetupOutput {
        context,
        metadata,
        params_bytes,
        pk_bytes,
        vk_bytes,
    })
}

fn module_id_to_string(module_id: &ModuleId) -> String {
    format!("{}::{}", module_id.address(), module_id.name())
}
