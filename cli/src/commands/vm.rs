// Copyright (c) zkMove Authors

use crate::api;
use crate::api::EntryArgument;
use crate::common::{
    get_circuit_config_args_from_move_toml, get_entry_call_from_move_toml,
    get_entry_info_from_move_toml, load_package, parse_module_id, read_params, save_to_file,
    ArgWithNameAndTypeJSON, HexEncodedBytes, KZGVariant,
};
use anyhow::{bail, Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use log::info;
use move_core_types::{language_storage::ModuleId, parser};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use vm_circuit::{public_inputs::PublicInputs, CircuitConfigArgs};
use witness::static_info::{EntryInfo, Footprints};

/// The binary files containing the circuit artifacts (params, pk, vk) and the metadata file.
const PARAMS_FILE: &str = "params.bin";
const PK_FILE: &str = "pk.bin";
const VK_FILE: &str = "vk.bin";
const CIRCUIT_METADATA_FILE: &str = "metadata.json";

/// The JSON file containing hex-encoded pk/vk/params for the circuit artifacts.
///  By default, this file is not emitted. Use the `--json` flag to emit it.
const CIRCUIT_ARTIFACTS_JSON_FILE: &str = "setup.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CircuitMetadata {
    k: u32,
    pubs_indices: Vec<usize>,
    /// Module id of the entry function, e.g. "0x1::fibonacci"
    module_id: String,
    function_name: String,
    function_index: u16,
    num_args: u8,
    config: CircuitConfigArgs,
}

impl CircuitMetadata {
    fn entry_info(&self) -> Result<EntryInfo> {
        Ok(EntryInfo {
            module_id: parse_module_id(&self.module_id)?,
            function_index: self.function_index,
            num_args: self.num_args,
        })
    }
}

#[derive(Parser)]
#[command(about = "Commands for witness generation, proving and verification in the client side.")]
pub struct VmCommands {
    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    #[command(about = "Compile the Move package (equivalent to `move build`)")]
    Compile(CompileCommand),

    #[command(
        name = "run",
        about = "Generate the witness by executing the entry function"
    )]
    Run(RunCommand),

    #[command(about = "Setup the circuit artifacts, optionally setup from a witness")]
    Setup(SetupCommand),

    #[command(
        about = "Generate proof by running the entry function of the circuit with the given arguments"
    )]
    Prove(ProveCommand),

    #[command(about = "Verify proof")]
    Verify(VerifyCommand),
}

#[derive(Parser)]
#[command(about = "Compile the Move package (equivalent to `move build`)")]
pub struct CompileCommand {
    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

    #[arg(
        long = "skip-fetch-latest-git-deps",
        help = "Skip fetching latest git dependencies",
        default_value_t = false
    )]
    skip_fetch_latest_git_deps: bool,
}

#[derive(Parser)]
#[command(about = "Generate the witness by executing the entry function")]
pub struct RunCommand {
    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

    #[arg(
        long = "module-id",
        value_parser = parse_module_id,
        help = "Module id of the entry function (e.g. 0x1::fibonacci)"
    )]
    module_id: ModuleId,

    #[arg(long = "function-name", help = "Name of the entry function")]
    function_name: String,

    #[arg(
        long = "args",
        value_parser = parser::parse_transaction_argument,
        num_args = 0..,
        help = "Entry function arguments (e.g. 10u64 true 0x1)"
    )]
    args: Vec<EntryArgument>,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save the witness (default: <package-path>/witnesses)"
    )]
    output_dir: Option<PathBuf>,
}

#[derive(Parser)]
#[command(about = "Setup the circuit artifacts, optionally setup from a witness")]
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
        short = 'w',
        long = "witness",
        help = "Path to .json file containing witness. If provided, setup the circuit from this witness."
    )]
    witness: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save circuit artifacts (default: <package-path>/setup)"
    )]
    output_dir: Option<PathBuf>,

    #[arg(
        long = "json",
        help = "Also emit a JSON file with hex-encoded pk/vk/params",
        default_value_t = false
    )]
    json: bool,
}

#[derive(Parser)]
#[command(about = "Generate proof by running the entry function of the circuit with the given arguments")]
pub struct ProveCommand {
    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

    #[arg(
        long = "setup-dir",
        help = "Directory containing circuit artifacts (default: <package-path>/setup)"
    )]
    circuit_artifacts_dir: Option<PathBuf>,

    #[arg(
        long = "kzg",
        value_enum,
        default_value_t = KZGVariant::GWC,
        help = "KZG commitment scheme variant"
    )]
    variant: KZGVariant,

    #[arg(
        long = "args",
        value_parser = parser::parse_transaction_argument,
        num_args = 0..,
        help = "Entry function arguments"
    )]
    args: Vec<EntryArgument>,


    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save proof/verification artifacts (default: <package-path>/proofs)"
    )]
    output_dir: Option<PathBuf>,

    #[arg(
        long = "json",
        help = "Also emit a JSON file with hex-encoded public_inputs/proof/vk",
        default_value_t = false
    )]
    json: bool,
}

#[derive(Parser)]
#[command(about = "Verify the proof")]
pub struct VerifyCommand {
    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

    #[arg(
        long = "setup-dir",
        help = "Directory containing circuit artifacts (default: <package-path>/setup)"
    )]
    circuit_artifacts_dir: Option<PathBuf>,

    #[arg(
        long = "kzg",
        value_enum,
        default_value_t = KZGVariant::GWC,
        help = "KZG commitment scheme variant"
    )]
    variant: KZGVariant,

    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf), required = true)]
    pubs_path: PathBuf,

    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf), required = true)]
    proof_path: PathBuf,
}

impl VmCommands {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            Subcommands::Compile(cmd) => cmd.run(),
            Subcommands::Run(cmd) => cmd.run(),
            Subcommands::Setup(cmd) => cmd.run(),
            Subcommands::Prove(cmd) => cmd.run(),
            Subcommands::Verify(cmd) => cmd.run(),
        }
    }
}

fn load_circuit_context_from_dir(
    package_path: &Path,
    circuit_artifacts_dir: &Path,
) -> Result<(api::VmCircuitContext, CircuitMetadata)> {
    let metadata_path = circuit_artifacts_dir.join(CIRCUIT_METADATA_FILE);
    let metadata_bytes = std::fs::read(&metadata_path).with_context(|| {
        format!(
            "Failed to read setup metadata from {}",
            metadata_path.display()
        )
    })?;
    let metadata: CircuitMetadata = serde_json::from_slice(&metadata_bytes).with_context(|| {
        format!(
            "Failed to parse setup metadata from {}",
            metadata_path.display()
        )
    })?;

    let params_path = circuit_artifacts_dir.join(PARAMS_FILE);
    let pk_path = circuit_artifacts_dir.join(PK_FILE);
    let vk_path = circuit_artifacts_dir.join(VK_FILE);

    let params_bytes = std::fs::read(&params_path)
        .with_context(|| format!("Failed to read setup params from {}", params_path.display()))?;
    let pk_bytes = std::fs::read(&pk_path).with_context(|| {
        format!(
            "Failed to read setup proving key from {}",
            pk_path.display()
        )
    })?;
    let vk_bytes = std::fs::read(&vk_path).with_context(|| {
        format!(
            "Failed to read setup verifying key from {}",
            vk_path.display()
        )
    })?;

    let package = load_package(package_path)?;
    let entry_info = metadata.entry_info()?;

    let context = api::VmCircuitContext::from_artifact_bytes(
        package,
        entry_info,
        metadata.config.clone(),
        metadata.k,
        metadata.pubs_indices.clone(),
        &params_bytes,
        &pk_bytes,
        &vk_bytes,
    )?;
    Ok((context, metadata))
}

impl CompileCommand {
    fn run(&self) -> Result<()> {
        let build_config = move_package::BuildConfig {
            skip_fetch_latest_git_deps: self.skip_fetch_latest_git_deps,
            ..Default::default()
        };
        build_config.compile_package(&self.package_path, &mut std::io::stdout())?;
        info!("Package compiled successfully");
        Ok(())
    }
}

impl RunCommand {
    fn run(&self) -> Result<()> {
        let package_path = &self.package_path;
        let package = load_package(package_path)?;

        let footprints = api::witness::generate_witness(
            &package,
            &self.module_id,
            &self.function_name,
            &self.args,
        )?;

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("witnesses"));
        std::fs::create_dir_all(&output_dir)?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let file_name = format!("{}-{}.json", self.function_name, timestamp);
        let content = serde_json::to_string_pretty(&footprints.0)?;
        save_to_file(&output_dir, &file_name, &content)?;

        info!("Witness saved to {}", output_dir.join(&file_name).display());
        Ok(())
    }
}

impl SetupCommand {
    fn run(&self) -> Result<()> {
        let package_path = &self.package_path;
        let manifest_path = package_path.join("Move.toml");
        let circuit_name = self.circuit_name.as_deref();
        let package = load_package(package_path)?;
        let (module_id, function_name) =
            get_entry_call_from_move_toml(&manifest_path, circuit_name)?;
        let entry_info = get_entry_info_from_move_toml(&manifest_path, circuit_name)?;
        let config = get_circuit_config_args_from_move_toml(&manifest_path, circuit_name)?;
        let params = read_params(&self.params_path)?;

        let context = if let Some(witness_path) = &self.witness {
            let traces = Footprints::load(witness_path).with_context(|| {
                format!("Failed to load witness from {}", witness_path.display())
            })?;
            let witness_entry = traces.entry().context("Entry not found in witness")?;
            if witness_entry != entry_info {
                bail!(
                    "witness entry {:?} does not match setup entry {:?}",
                    witness_entry,
                    entry_info
                );
            }
            api::setup::setup_with_witness(
                package,
                &traces,
                config,
                params,
                self.pubs_indices.clone(),
            )?
        } else {
            api::setup::setup(
                package,
                entry_info,
                config,
                params,
                self.pubs_indices.clone(),
            )?
        };

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("setup"));
        std::fs::create_dir_all(&output_dir)?;

        let params_bytes = context.params_bytes()?;
        let pk_bytes = context.pk_bytes()?;
        let vk_bytes = context.vk_bytes();

        save_to_file(&output_dir, PARAMS_FILE, &params_bytes)?;
        save_to_file(&output_dir, PK_FILE, &pk_bytes)?;
        save_to_file(&output_dir, VK_FILE, &vk_bytes)?;
        let metadata = CircuitMetadata {
            k: context.k,
            pubs_indices: context.pubs_indices.clone(),
            module_id: format!(
                "{}::{}",
                module_id.address().to_hex_literal(),
                module_id.name()
            ),
            function_name,
            function_index: context.entry_info.function_index,
            num_args: context.entry_info.num_args,
            config: context.config.clone(),
        };
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        save_to_file(&output_dir, CIRCUIT_METADATA_FILE, &metadata_json)?;

        if self.json {
            let content = vec![
                ArgWithNameAndTypeJSON {
                    name: "params".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(params_bytes).to_string()),
                },
                ArgWithNameAndTypeJSON {
                    name: "pk".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(pk_bytes).to_string()),
                },
                ArgWithNameAndTypeJSON {
                    name: "vk".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(vk_bytes).to_string()),
                },
            ];
            let json_output = serde_json::to_string_pretty(&content)?;
            save_to_file(&output_dir, CIRCUIT_ARTIFACTS_JSON_FILE, &json_output)?;
        }

        info!(
            "Circuit artifacts saved to {} (k = {})",
            output_dir.display(),
            context.k
        );
        Ok(())
    }
}

impl ProveCommand {
    fn run(&self) -> Result<()> {
        let package_path = &self.package_path;
        let circuit_artifacts_dir = self
            .circuit_artifacts_dir
            .clone()
            .unwrap_or_else(|| package_path.join("setup"));
        let (circuit_context, metadata) =
            load_circuit_context_from_dir(package_path, &circuit_artifacts_dir)?;

        let module_id = parse_module_id(&metadata.module_id)?;
        let function_name = metadata.function_name.clone();
        let output = api::prove::prove(
            &circuit_context,
            &module_id,
            &function_name,
            &self.args,
            self.variant,
        )?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let file_stem = format!("{}-{}", function_name, timestamp);

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("proofs"));
        std::fs::create_dir_all(&output_dir)?;

        save_to_file(&output_dir, &format!("{}.proof", file_stem), &output.proof)?;
        save_to_file(
            &output_dir,
            &format!("{}.instance", file_stem),
            &output.instance,
        )?;
        let vk_bytes = circuit_context.vk_bytes();
        save_to_file(&output_dir, &format!("{}.vk", file_stem), &vk_bytes)?;

        if self.json {
            let public_inputs = PublicInputs::<Fr>::from_bytes(&output.instance);
            let content = vec![
                ArgWithNameAndTypeJSON {
                    name: "public_inputs".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(public_inputs
                        .as_vec()
                        .into_iter()
                        .map(|is| is
                            .iter()
                            .map(|fr| fr.to_repr().as_ref().to_vec())
                            .map(|d| HexEncodedBytes(d).to_string())
                            .collect::<Vec<_>>())
                        .collect::<Vec<_>>()),
                },
                ArgWithNameAndTypeJSON {
                    name: "proof".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(output.proof.clone()).to_string()),
                },
                ArgWithNameAndTypeJSON {
                    name: "vk".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(vk_bytes.clone()).to_string()),
                },
            ];
            let json_output = serde_json::to_string_pretty(&content)?;
            save_to_file(&output_dir, &format!("{}.json", file_stem), &json_output)?;
        }

        info!(
            "Proof artifacts saved to {} (k = {})",
            output_dir.display(),
            circuit_context.k
        );
        Ok(())
    }
}

impl VerifyCommand {
    fn run(&self) -> Result<()> {
        let package_path = &self.package_path;
        let circuit_artifacts_dir = self
            .circuit_artifacts_dir
            .clone()
            .unwrap_or_else(|| package_path.join("setup"));
        let (circuit_context, _metadata) =
            load_circuit_context_from_dir(package_path, &circuit_artifacts_dir)?;

        let proof = std::fs::read(&self.proof_path)?;
        let pubs_bytes = std::fs::read(&self.pubs_path)?;

        api::verify::verify(&circuit_context, self.variant, &proof, &pubs_bytes)?;

        info!("Proof verified successfully");
        Ok(())
    }
}
