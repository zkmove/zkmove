// Copyright (c) zkMove Authors

use crate::api::circuit::build_circuit_and_fit_params;
use crate::common::{
    get_circuit_config_args_from_move_toml, load_package, read_params, save_txn_output, KZGVariant,
};
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{setup_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::kzg::commitment::ParamsKZG,
};
use log::info;
use move_package::compilation::compiled_package::CompiledPackage;
use std::path::PathBuf;
use sui_verifier_api::native_verifier::{
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
use sui_verifier_api::SuiMoveCallJSON;
use vm_circuit::{public_inputs::PublicInputs, CircuitConfigArgs};
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
        let json = build_publish_params_native(
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

        let json = build_publish_circuit_native(
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

        let json = build_verify_proof_native(
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

fn build_publish_params_native(
    params: &ParamsKZG<Bn256>,
    verifier_api_package: &str,
    params_store_object_id: &str,
) -> Result<SuiMoveCallJSON> {
    build_publish_params_native_transaction_payload(
        params,
        verifier_api_package,
        params_store_object_id,
    )
}

fn build_publish_circuit_native(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    verifier_api_package: &str,
) -> Result<SuiMoveCallJSON> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params)?;

    let (vk, _pk) = setup_circuit(&*circuit, params)
        .map_err(|e| anyhow::anyhow!("Failed to setup circuit: {:?}", e))?;

    build_publish_vk_native_transaction_payload(&vk, params, circuit.as_ref(), verifier_api_package)
}

#[allow(clippy::too_many_arguments)]
fn build_verify_proof_native(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    verifier_api_package: &str,
    params_object_id: &str,
    vk_object_id: &str,
    k: Option<u32>,
) -> Result<SuiMoveCallJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_native_transaction_payload::<G1Affine>(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        verifier_api_package,
        params_object_id,
        vk_object_id,
        k,
    )
}
