use crate::{save_to_file, KZGVariant};
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::KZG;
use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use log::info;
use std::env::current_dir;
use std::path::{Path, PathBuf};
use sui_verifier_api::native_verifier::build_verify_proof_native_transaction_payload;
use sui_verifier_api::DEFAULT_HALO2_KZG_PACKAGE;
use vm_circuit::public_inputs::PublicInputs;

#[derive(Parser)]
#[command(about = "Generate Sui txns for verify proof on Sui")]
pub struct SuiCommands {
    #[arg(short = 'd', long = "debug", help = "debug mode")]
    debug: bool,
    #[command(subcommand)]
    command: SuiSubcommands,
}

impl SuiCommands {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            SuiSubcommands::BuildVerifyProofNativeSuiTxn(cmd) => cmd.run(),
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum SuiSubcommands {
    BuildVerifyProofNativeSuiTxn(BuildVerifyProofNativeSuiTxn),
}

#[derive(Parser)]
struct BuildVerifyProofNativeSuiTxn {
    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf))]
    pubs_path: PathBuf,
    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser!(PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long = "halo2-kzg-package", default_value = DEFAULT_HALO2_KZG_PACKAGE)]
    halo2_kzg_package: String,
    #[arg(long = "params-object-id")]
    params_object_id: String,
    #[arg(long = "vk-object-id")]
    vk_object_id: String,
    #[arg(long = "circuit-object-id")]
    circuit_object_id: String,
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
        let kzg = match self.variant {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        };
        let proof = std::fs::read(&self.proof_path)
            .with_context(|| format!("Failed to read proof from {:?}", self.proof_path))?;
        let pubs = std::fs::read(&self.pubs_path)
            .with_context(|| format!("Failed to read pubs from {:?}", self.pubs_path))?;
        let public_inputs = PublicInputs::<Fr>::from_bytes(&pubs);
        let json = build_verify_proof_native_transaction_payload::<G1Affine>(
            proof,
            kzg as u8,
            public_inputs.as_vec(),
            self.halo2_kzg_package.as_str(),
            self.params_object_id.as_str(),
            self.vk_object_id.as_str(),
            self.circuit_object_id.as_str(),
            self.k,
        )?;

        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.proof_path,
            "verify-proof-native-sui",
            &output,
        )?;
        info!("Transaction built successfully.");
        Ok(())
    }
}

fn save_txn_output(
    output_dir: Option<PathBuf>,
    input_path: &Path,
    suffix: &str,
    content: &str,
) -> Result<()> {
    let output_dir = output_dir.unwrap_or_else(|| current_dir().unwrap());
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output directory at {:?}", output_dir))?;
    let file_stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
    save_to_file(
        &output_dir,
        &format!("{}-{}.txn", file_stem, suffix),
        content,
    )
}
