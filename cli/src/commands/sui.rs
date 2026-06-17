// Copyright (c) zkMove Authors

use crate::common::{
    get_circuit_config_args_from_move_toml, load_package, read_params, save_txn_output, KZGVariant,
};
use crate::ops;
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2_proofs::halo2curves::bn256::Fr;
use log::info;
use std::path::PathBuf;
use vm_circuit::public_inputs::PublicInputs;
use witness::static_info::Footprints;

#[derive(Parser)]
#[command(about = "Generate Sui txns for verify proof on Sui")]
pub struct SuiCommands {
    #[command(subcommand)]
    command: SuiSubcommands,
}

impl SuiCommands {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            SuiSubcommands::BuildPublishParamsNativeSuiTxn(cmd) => cmd.run(),
            SuiSubcommands::BuildPublishCircuitNativeSuiTxn(cmd) => cmd.run(),
            SuiSubcommands::BuildVerifyProofNativeSuiTxn(cmd) => cmd.run(),
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum SuiSubcommands {
    #[command(name = "build-publish-params-native-txn")]
    BuildPublishParamsNativeSuiTxn(BuildPublishParamsNativeSuiTxn),
    #[command(name = "build-publish-circuit-native-txn")]
    BuildPublishCircuitNativeSuiTxn(BuildPublishCircuitNativeSuiTxn),
    #[command(
        name = "build-verify-proof-native-txn",
        alias = "build-verify-proof-native-sui-txn"
    )]
    BuildVerifyProofNativeSuiTxn(BuildVerifyProofNativeSuiTxn),
}

#[derive(Parser)]
struct BuildPublishParamsNativeSuiTxn {
    #[arg(long, help = "params file used for prove/verify in kzg")]
    params_path: PathBuf,
    #[arg(long = "verifier-api-package")]
    verifier_api_package: String,
    #[arg(long = "params-store-object-id", default_value = "0x1")]
    params_store_object_id: String,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the txn")]
    output_dir: Option<PathBuf>,
}

impl BuildPublishParamsNativeSuiTxn {
    pub fn run(&self) -> Result<()> {
        let params = read_params(&self.params_path)?;
        let json = ops::sui::build_publish_params_native(
            &params,
            &self.verifier_api_package,
            &self.params_store_object_id,
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.params_path,
            "publish-params-native",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildPublishCircuitNativeSuiTxn {
    #[arg(long, help = "params file used for prove/verify in kzg")]
    params_path: PathBuf,
    #[arg(long = "package-dir", short = 'p', value_parser = value_parser!(PathBuf))]
    package_dir: PathBuf,
    #[arg(
        long = "circuit-name",
        short = 'c',
        help = "Name of the circuit section in Move.toml (e.g. fibonacci for [circuit.fibonacci]). If omitted, uses the plain [circuit] section in Move.toml."
    )]
    circuit_name: Option<String>,
    #[arg(
        short = 'w',
        long = "witness",
        help = "path to .json file containing witness"
    )]
    witness: PathBuf,
    #[arg(long = "verifier-api-package")]
    verifier_api_package: String,
    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g., --pubs-indices 0 1)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the txn")]
    output_dir: Option<PathBuf>,
}

impl BuildPublishCircuitNativeSuiTxn {
    pub fn run(&self) -> Result<()> {
        let mut params = read_params(&self.params_path)?;
        let package = load_package(&self.package_dir)?;
        let config = get_circuit_config_args_from_move_toml(
            &self.package_dir.join("Move.toml"),
            self.circuit_name.as_deref(),
        )?;

        info!("Loading witness from {:?}", self.witness.display());
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {:?}", self.witness))?;

        let json = ops::sui::build_publish_circuit_native(
            &package,
            &traces,
            config,
            &self.pubs_indices,
            &mut params,
            &self.verifier_api_package,
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-vk-native",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildVerifyProofNativeSuiTxn {
    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf))]
    pubs_path: PathBuf,
    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser!(PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long = "verifier-api-package")]
    verifier_api_package: String,
    #[arg(long = "params-object-id")]
    params_object_id: String,
    #[arg(long = "vk-object-id")]
    vk_object_id: String,
    #[arg(long = "kzg", value_enum, default_value_t = KZGVariant::GWC)]
    variant: KZGVariant,
    #[arg(
        long = "k",
        help = "optional new parameter k to downsize the KZG parameters if needed"
    )]
    k: Option<u32>,
}

impl BuildVerifyProofNativeSuiTxn {
    pub fn run(&self) -> Result<()> {
        let proof = std::fs::read(&self.proof_path)
            .with_context(|| format!("Failed to read proof from {:?}", self.proof_path))?;
        let pubs = std::fs::read(&self.pubs_path)
            .with_context(|| format!("Failed to read pubs from {:?}", self.pubs_path))?;
        let public_inputs = PublicInputs::<Fr>::from_bytes(&pubs);

        let json = ops::sui::build_verify_proof_native(
            proof,
            &public_inputs,
            self.variant,
            &self.verifier_api_package,
            &self.params_object_id,
            &self.vk_object_id,
            self.k,
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.proof_path,
            "verify-proof-native",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}
