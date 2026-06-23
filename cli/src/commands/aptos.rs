// Copyright (c) zkMove Authors

use crate::api::circuit::build_circuit_and_fit_params;
use crate::common::{
    get_circuit_config_args_from_move_toml, load_package, read_params, save_txn_output, KZGVariant,
};
use anyhow::{Context, Result};
use aptos_verifier_api::native_verifier::{
    build_publish_circuit_native_transaction_payload,
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
use aptos_verifier_api::verifier::{
    build_publish_circuit_transaction_payload, build_publish_params_transaction_payload,
    build_verify_proof_transaction_payload,
};
use aptos_verifier_api::EntryFunctionArgumentsJSON;
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{setup_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::kzg::commitment::ParamsKZG,
};
use log::info;
use move_package::compilation::compiled_package::CompiledPackage;
use std::path::PathBuf;
use vm_circuit::{public_inputs::PublicInputs, CircuitConfigArgs};
use witness::static_info::Footprints;

#[derive(Parser)]
#[command(about = "Generate aptos txns for verify proof on aptos")]
pub struct AptosCommands {
    #[command(subcommand)]
    command: AptosSubcommands,
}
impl AptosCommands {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            AptosSubcommands::BuildPublishParamsAptosTxn(cmd) => cmd.run(),
            AptosSubcommands::BuildPublishCircuitAptosTxn(cmd) => cmd.run(),
            AptosSubcommands::BuildVerifyProofAptosTxn(cmd) => cmd.run(),
            AptosSubcommands::BuildPublishParamsNativeAptosTxn(cmd) => cmd.run(),
            AptosSubcommands::BuildPublishCircuitNativeAptosTxn(cmd) => cmd.run(),
            AptosSubcommands::BuildVerifyProofNativeAptosTxn(cmd) => cmd.run(),
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum AptosSubcommands {
    BuildPublishParamsAptosTxn(BuildPublishParamsAptosTxn),
    BuildPublishCircuitAptosTxn(BuildPublishCircuitAptosTxn),
    BuildVerifyProofAptosTxn(BuildVerifyProofAptosTxn),
    BuildPublishParamsNativeAptosTxn(BuildPublishParamsNativeAptosTxn),
    BuildPublishCircuitNativeAptosTxn(BuildPublishCircuitNativeAptosTxn),
    #[command(
        name = "build-verify-proof-native-txn",
        alias = "build-verify-proof-native-aptos-txn"
    )]
    BuildVerifyProofNativeAptosTxn(BuildVerifyProofNativeAptosTxn),
}

#[derive(Parser)]
struct BuildPublishParamsAptosTxn {
    #[arg(long, help = "params file used for prove/verify in kzg")]
    params_path: PathBuf,
    #[arg(long = "params-contract-address")]
    params_contract_address: String,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the proof")]
    output_dir: Option<PathBuf>,
}

impl BuildPublishParamsAptosTxn {
    pub fn run(&self) -> Result<()> {
        let params = read_params(&self.params_path)?;
        let json = build_publish_params(&params, &self.params_contract_address)?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.params_path,
            "publish-params",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildPublishCircuitAptosTxn {
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
    #[arg(long = "verifier-contract-address")]
    verifier_contract_address: String,
    #[arg(
        short = 'w',
        long = "witness",
        help = "path to .json file containing witness"
    )]
    witness: PathBuf,
    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g., --pubs-indices 0 1)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the proof")]
    output_dir: Option<PathBuf>,
}
impl BuildPublishCircuitAptosTxn {
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

        let json = build_publish_circuit(
            &package,
            &traces,
            config,
            &self.pubs_indices,
            &mut params,
            &self.verifier_contract_address,
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-circuit",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildVerifyProofAptosTxn {
    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf))]
    pubs_path: PathBuf,
    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser!(PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long = "verifier-contract-address")]
    verifier_contract_address: String,
    #[arg(long = "params-address")]
    params_address: String,
    #[arg(long = "verifier-address")]
    verifier_address: String,
    #[arg(long = "kzg", value_enum, default_value_t = KZGVariant::GWC)]
    variant: KZGVariant,
}
impl BuildVerifyProofAptosTxn {
    pub fn run(&self) -> Result<()> {
        let proof = std::fs::read(&self.proof_path)
            .with_context(|| format!("Failed to read proof from {:?}", self.proof_path))?;
        let pubs = std::fs::read(&self.pubs_path)
            .with_context(|| format!("Failed to read pubs from {:?}", self.pubs_path))?;
        let public_inputs = PublicInputs::<Fr>::from_bytes(&pubs);

        let json = build_verify_proof(
            proof,
            &public_inputs,
            self.variant,
            &self.verifier_contract_address,
            &self.verifier_address,
            &self.params_address,
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.proof_path,
            "verify-proof",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildPublishParamsNativeAptosTxn {
    #[arg(long, help = "params file used for prove/verify in kzg")]
    params_path: PathBuf,
    #[arg(long = "params-contract-address")]
    params_contract_address: String,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the proof")]
    output_dir: Option<PathBuf>,
}

impl BuildPublishParamsNativeAptosTxn {
    pub fn run(&self) -> Result<()> {
        let params = read_params(&self.params_path)?;
        let json = build_publish_params_native(&params, &self.params_contract_address)?;
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
struct BuildPublishCircuitNativeAptosTxn {
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
    #[arg(long = "native-verifier-contract-address")]
    native_verifier_contract_address: String,
    #[arg(
        short = 'w',
        long = "witness",
        help = "path to .json file containing witness"
    )]
    witness: PathBuf,
    #[arg(
        long = "pubs-indices",
        help = "Indices of arguments to be treated as public inputs (e.g., --pubs-indices 0 1)",
        value_parser = clap::value_parser!(usize),
        num_args = 0..,
    )]
    pubs_indices: Vec<usize>,
    #[arg(short = 'o', long = "output-dir", help = "directory to save the proof")]
    output_dir: Option<PathBuf>,
}

impl BuildPublishCircuitNativeAptosTxn {
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

        let txns = build_publish_circuit_native(
            &package,
            &traces,
            config,
            &self.pubs_indices,
            &mut params,
            &self.native_verifier_contract_address,
        )?;

        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-vk-native",
            &serde_json::to_string_pretty(&txns.vk)?,
        )?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-circuit-native",
            &serde_json::to_string_pretty(&txns.circuit)?,
        )?;
        info!("Transactions built successfully.");
        Ok(())
    }
}

#[derive(Parser)]
struct BuildVerifyProofNativeAptosTxn {
    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf))]
    pubs_path: PathBuf,
    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser!(PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long = "native-verifier-contract-address")]
    native_verifier_contract_address: String,
    #[arg(long = "params-address")]
    params_address: String,
    #[arg(long = "native-verifier-address")]
    native_verifier_address: String,
    #[arg(long = "kzg", value_enum, default_value_t = KZGVariant::GWC)]
    variant: KZGVariant,
    #[arg(
        long = "k",
        help = "optional new parameter k to downsize the KZG parameters if needed"
    )]
    k: Option<u32>,
}

impl BuildVerifyProofNativeAptosTxn {
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
            &self.native_verifier_contract_address,
            &self.native_verifier_address,
            &self.params_address,
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

struct NativeCircuitTxns {
    vk: EntryFunctionArgumentsJSON,
    circuit: EntryFunctionArgumentsJSON,
}

fn build_publish_params(
    params: &ParamsKZG<Bn256>,
    params_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    build_publish_params_transaction_payload(params, params_contract_address)
}

fn build_publish_circuit(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    verifier_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params)?;

    build_publish_circuit_transaction_payload(params, circuit.as_ref(), verifier_contract_address)
}

fn build_verify_proof(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    verifier_contract_address: &str,
    verifier_address: &str,
    params_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_transaction_payload(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        verifier_contract_address,
        verifier_address,
        params_address,
    )
}

fn build_publish_params_native(
    params: &ParamsKZG<Bn256>,
    params_contract_address: &str,
) -> Result<EntryFunctionArgumentsJSON> {
    build_publish_params_native_transaction_payload(params, params_contract_address.to_string())
}

fn build_publish_circuit_native(
    package: &CompiledPackage,
    traces: &Footprints,
    config: CircuitConfigArgs,
    pubs_indices: &[usize],
    params: &mut ParamsKZG<Bn256>,
    native_verifier_contract_address: &str,
) -> Result<NativeCircuitTxns> {
    let (circuit, _circuit_guard, _k) =
        build_circuit_and_fit_params(package, traces, config, pubs_indices, params)?;

    let (vk, _pk) = setup_circuit(&*circuit, params)
        .map_err(|e| anyhow::anyhow!("Failed to setup circuit: {:?}", e))?;

    let vk_txn = build_publish_vk_native_transaction_payload(
        &vk,
        native_verifier_contract_address.to_string(),
    )?;
    let circuit_txn = build_publish_circuit_native_transaction_payload(
        params,
        circuit.as_ref(),
        native_verifier_contract_address.to_string(),
    )?;

    Ok(NativeCircuitTxns {
        vk: vk_txn,
        circuit: circuit_txn,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_verify_proof_native(
    proof: Vec<u8>,
    public_inputs: &PublicInputs<Fr>,
    variant: KZGVariant,
    native_verifier_contract_address: &str,
    native_verifier_address: &str,
    params_address: &str,
    k: Option<u32>,
) -> Result<EntryFunctionArgumentsJSON> {
    let kzg = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    build_verify_proof_native_transaction_payload::<G1Affine>(
        proof,
        kzg as u8,
        public_inputs.as_vec(),
        native_verifier_contract_address,
        native_verifier_address,
        params_address,
        k,
    )
}
