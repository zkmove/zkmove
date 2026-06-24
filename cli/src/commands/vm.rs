// Copyright (c) zkMove Authors

use crate::api;
use crate::api::circuit::build_empty_circuit_and_fit_params;
use crate::api::context::VmCircuitContext;
use crate::common::{
    get_circuit_config_args_from_move_toml, get_entry_call_from_move_toml,
    get_entry_info_from_move_toml, load_package, read_params, save_to_file, ArgWithNameAndTypeJSON,
    HexEncodedBytes, KZGVariant,
};
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::setup_circuit;
use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, Fr},
        ff::PrimeField,
    },
    poly::kzg::commitment::ParamsKZG,
};
use halo2_verifier::{test_verifier, KZG as VerifierKZG};
use log::info;
use move_cli::sandbox::utils::OnDiskStateView;
use move_compiler::compiled_unit::CompiledUnitEnum;
use move_core_types::language_storage::TypeTag;
use move_core_types::parser;
use move_core_types::transaction_argument::TransactionArgument;
use move_package::compilation::compiled_package::CompiledPackage;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use vm_circuit::{public_inputs::PublicInputs, CircuitConfigArgs, VmCircuit};
use witness::static_info::{EntryInfo, Footprints};

const DEFAULT_STORAGE_DIR: &str = "storage";
const SETUP_PARAMS_FILE: &str = "params.bin";
const SETUP_PK_FILE: &str = "pk.bin";
const SETUP_VK_FILE: &str = "vk.bin";

#[derive(Parser)]
#[command(about = "Commands for witness generation, proving and verification in the client side.")]
pub struct VmCommands {
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

    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    #[command(
        name = "dry-run",
        about = "Generate the witness by executing the entry function"
    )]
    DryRun(DryRunCommand),

    #[command(about = "Generate app-developer setup artifacts for SDK initialization")]
    Setup(SetupCommand),

    #[command(about = "Generate proof based on witness")]
    Prove(ProveCommand),

    #[command(about = "Verify proof")]
    Verify(VerifyCommand),

    #[command(about = "Test the on-chain verifier on provided witness files")]
    Test(TestCommand),
}

#[derive(Parser)]
#[command(about = "Generate the witness by executing the entry function")]
pub struct DryRunCommand {
    #[arg(
        long = "args",
        value_parser = parser::parse_transaction_argument,
        num_args = 0..,
        help = "Entry function arguments (e.g. 10u64 true 0x1)"
    )]
    args: Vec<TransactionArgument>,

    #[arg(
        long = "type-args",
        value_parser = parser::parse_type_tag,
        num_args = 0..,
        help = "Type arguments for the entry function"
    )]
    type_args: Vec<TypeTag>,

    #[arg(
        long = "signers",
        num_args = 0..,
        help = "Signer addresses passed ahead of --args (e.g. 0x1)"
    )]
    signers: Vec<String>,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save the witness (default: <package-path>/witnesses)"
    )]
    output_dir: Option<PathBuf>,
}

#[derive(Parser)]
#[command(about = "Generate app-developer setup artifacts for SDK initialization")]
pub struct SetupCommand {
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

#[derive(Parser)]
#[command(about = "Generate proof based on witness")]
pub struct ProveCommand {
    #[arg(long, help = "Params file used for prove in kzg")]
    params_path: PathBuf,

    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g. 0 1 3)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,

    #[arg(
        long = "kzg",
        value_enum,
        default_value_t = KZGVariant::GWC,
        help = "KZG commitment scheme variant"
    )]
    variant: KZGVariant,

    #[arg(
        short = 'w',
        long = "witness",
        help = "Path to .json file containing witness",
        required = true
    )]
    witness: PathBuf,

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
    #[arg(long, help = "Params file used for verify in kzg")]
    params_path: PathBuf,

    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g. 0 1 3)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,

    #[arg(
        long = "kzg",
        value_enum,
        default_value_t = KZGVariant::GWC,
        help = "KZG commitment scheme variant"
    )]
    variant: KZGVariant,

    #[arg(
        short = 'k',
        help = "Degree of the KZG params (k), reported when proving",
        required = true
    )]
    k: u32,

    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf), required = true)]
    pubs_path: PathBuf,

    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf), required = true)]
    proof_path: PathBuf,
}

#[derive(Parser)]
#[command(about = "Test the on-chain verifier on provided witness files")]
pub struct TestCommand {
    #[arg(long, help = "Params file used for prove in kzg")]
    params_path: PathBuf,

    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g. 0 1 3)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,

    #[arg(
        long = "kzg",
        value_enum,
        default_value_t = KZGVariant::GWC,
        help = "KZG commitment scheme variant"
    )]
    variant: KZGVariant,

    #[arg(
        short = 'w',
        long = "witness",
        help = "Path to .json file containing witness",
        required = true
    )]
    witness: PathBuf,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save proof/verification artifacts (default: <package-path>/proofs)"
    )]
    output_dir: Option<PathBuf>,
}

impl VmCommands {
    pub fn run(&self) -> Result<()> {
        let manifest_path = self.package_path.join("Move.toml");
        let circuit_name = self.circuit_name.as_deref();
        match &self.command {
            Subcommands::DryRun(cmd) => cmd.run(&self.package_path, &manifest_path, circuit_name),
            Subcommands::Setup(cmd) => cmd.run(&self.package_path, &manifest_path, circuit_name),
            Subcommands::Prove(cmd) => cmd.run(&self.package_path, &manifest_path, circuit_name),
            Subcommands::Verify(cmd) => cmd.run(&self.package_path, &manifest_path, circuit_name),
            Subcommands::Test(cmd) => cmd.run(&self.package_path, &manifest_path, circuit_name),
        }
    }
}

fn witness_file_stem(witness: &Path) -> Result<&str> {
    witness
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid witness filename"))
}

fn prepare_witness_state(
    package_path: &Path,
    package: &CompiledPackage,
) -> Result<OnDiskStateView> {
    let storage_dir = package_path.join(DEFAULT_STORAGE_DIR);
    let state = OnDiskStateView::create(package_path, storage_dir.as_path())?;

    // The freshly compiled package is the source of truth, so overwrite modules in
    // storage before execution rather than reusing stale bytecode.
    for cu in package.all_modules() {
        if let CompiledUnitEnum::Module(named) = &cu.unit {
            let id = named.module.self_id();
            state.save_module(&id, &cu.unit.serialize(None))?;
        }
    }

    Ok(state)
}

pub(crate) fn setup(
    package: CompiledPackage,
    entry_info: EntryInfo,
    config: CircuitConfigArgs,
    mut params: ParamsKZG<Bn256>,
    pubs_indices: Vec<usize>,
) -> Result<VmCircuitContext> {
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

    Ok(VmCircuitContext::from_parts(
        package,
        entry_info,
        config,
        params,
        pk,
        vk,
        k,
        pubs_indices,
    ))
}

impl DryRunCommand {
    fn run(
        &self,
        package_path: &Path,
        manifest_path: &Path,
        circuit_name: Option<&str>,
    ) -> Result<()> {
        let (module_id, function_name) =
            get_entry_call_from_move_toml(manifest_path, circuit_name)?;
        let package = load_package(package_path)?;
        let state = prepare_witness_state(package_path, &package)?;

        let footprints = api::dry_run::generate_witness_in_storage(
            &state,
            &module_id,
            &function_name,
            self.type_args.clone(),
            &self.args,
            &self.signers,
        )?;

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("witnesses"));
        std::fs::create_dir_all(&output_dir)?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let file_name = format!("{}-{}.json", function_name, timestamp);
        let content = serde_json::to_string_pretty(&footprints.0)?;
        save_to_file(&output_dir, &file_name, &content)?;

        info!("Witness saved to {}", output_dir.join(&file_name).display());
        Ok(())
    }
}

impl SetupCommand {
    fn run(
        &self,
        package_path: &Path,
        manifest_path: &Path,
        circuit_name: Option<&str>,
    ) -> Result<()> {
        let package = load_package(package_path)?;
        let entry_info = get_entry_info_from_move_toml(manifest_path, circuit_name)?;
        let config = get_circuit_config_args_from_move_toml(manifest_path, circuit_name)?;
        let params = read_params(&self.params_path)?;

        let context = setup(
            package,
            entry_info,
            config,
            params,
            self.pubs_indices.clone(),
        )?;

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("setup"));
        std::fs::create_dir_all(&output_dir)?;

        save_to_file(&output_dir, SETUP_PARAMS_FILE, context.params_bytes()?)?;
        save_to_file(&output_dir, SETUP_PK_FILE, context.pk_bytes()?)?;
        save_to_file(&output_dir, SETUP_VK_FILE, context.vk_bytes())?;

        info!(
            "Setup artifacts saved to {} (k = {})",
            output_dir.display(),
            context.k
        );
        Ok(())
    }
}

impl ProveCommand {
    fn run(
        &self,
        package_path: &Path,
        manifest_path: &Path,
        circuit_name: Option<&str>,
    ) -> Result<()> {
        let params = read_params(&self.params_path)?;
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {}", self.witness.display()))?;
        let package = load_package(package_path)?;
        let config = get_circuit_config_args_from_move_toml(manifest_path, circuit_name)?;
        let entry_info = get_entry_info_from_move_toml(manifest_path, circuit_name)?;

        let setup_context = setup(
            package,
            entry_info,
            config,
            params,
            self.pubs_indices.clone(),
        )?;
        let output = api::prove::prove_with_witness(&setup_context, &traces, self.variant)?;

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("proofs"));
        std::fs::create_dir_all(&output_dir)?;

        let file_stem = witness_file_stem(&self.witness)?;
        save_to_file(&output_dir, &format!("{}.proof", file_stem), &output.proof)?;
        save_to_file(
            &output_dir,
            &format!("{}.instance", file_stem),
            &output.instance,
        )?;
        let vk_bytes = setup_context.vk_bytes();
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
            setup_context.k
        );
        Ok(())
    }
}

impl VerifyCommand {
    fn run(
        &self,
        package_path: &Path,
        manifest_path: &Path,
        circuit_name: Option<&str>,
    ) -> Result<()> {
        let params = read_params(&self.params_path)?;
        let config = get_circuit_config_args_from_move_toml(manifest_path, circuit_name)?;
        let entry_info = get_entry_info_from_move_toml(manifest_path, circuit_name)?;
        let package = load_package(package_path)?;
        let setup_context = setup(
            package,
            entry_info,
            config,
            params,
            self.pubs_indices.clone(),
        )?;

        let proof = std::fs::read(&self.proof_path)?;
        let pubs_bytes = std::fs::read(&self.pubs_path)?;

        if self.k != setup_context.k {
            log::warn!(
                "provided k ({}) differs from setup k ({}); using setup context k",
                self.k,
                setup_context.k
            );
        }

        api::verify::verify(&setup_context, self.variant, &proof, &pubs_bytes)?;

        info!("Proof verified successfully");
        Ok(())
    }
}

impl TestCommand {
    fn run(
        &self,
        package_path: &Path,
        manifest_path: &Path,
        circuit_name: Option<&str>,
    ) -> Result<()> {
        let mut params = read_params(&self.params_path)?;
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {}", self.witness.display()))?;
        let package = load_package(package_path)?;
        let config = get_circuit_config_args_from_move_toml(manifest_path, circuit_name)?;

        let (circuit, _circuit_guard, _k) = api::circuit::build_circuit_and_fit_params(
            &package,
            &traces,
            config,
            &self.pubs_indices,
            &mut params,
        )?;

        let args = traces.args().context("Arguments not found in witness")?;
        let public_inputs = PublicInputs::new(&args, &self.pubs_indices);

        let (_vk, _pk) = setup_circuit(&*circuit, &params).expect("setup should not fail");

        let verifier_kzg_scheme = match self.variant {
            KZGVariant::GWC => VerifierKZG::GWC,
            KZGVariant::SHPLONK => VerifierKZG::SHPLONK,
        };

        let test_data = test_verifier(
            circuit.as_ref().clone(),
            public_inputs.as_vec(),
            &params,
            verifier_kzg_scheme,
        )
        .expect("on-chain verifier test should not fail");

        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| package_path.join("proofs"));
        std::fs::create_dir_all(&output_dir)?;

        let file_stem = witness_file_stem(&self.witness)?;
        let json_content = serde_json::to_string_pretty(&json!({
            "serialized_params": HexEncodedBytes(test_data.serialized_params).to_string(),
            "vk_bytes": HexEncodedBytes(test_data.vk_bytes).to_string(),
            "circuit_info_bytes": HexEncodedBytes(test_data.circuit_info_bytes).to_string(),
            "proof": HexEncodedBytes(test_data.proof).to_string(),
            "public_inputs_bytes": HexEncodedBytes(test_data.public_inputs_bytes).to_string(),
        }))?;

        save_to_file(
            &output_dir,
            &format!("{}.verifier.json", file_stem),
            &json_content,
        )?;
        info!("Verifier test data saved to {}", output_dir.display());
        Ok(())
    }
}
