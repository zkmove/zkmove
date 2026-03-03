use crate::get_circuit_config_args_from_move_toml;
use crate::load_package;
use crate::save_to_file;
use crate::KZGVariant;
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
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{best_k, setup_circuit, KZG};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::info;
use std::path::{Path, PathBuf};
use std::{env::current_dir, rc::Rc};
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitGuard, VmCircuit};
use witness::static_info::Footprints;

#[derive(Parser)]
#[command(about = "Generate aptos txns for verify proof on aptos")]
pub struct AptosCommands {
    #[arg(short = 'd', long = "debug", help = "debug mode")]
    debug: bool,
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
        let mut params_file = std::fs::File::open(self.params_path.as_path())?;
        let params = ParamsKZG::<Bn256>::read(&mut params_file)?;

        let json = build_publish_params_transaction_payload(
            &params,
            self.params_contract_address.as_str(),
        )?;
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
    #[arg(short = 'd', long = "debug", help = "debug with mock prover")]
    debug: bool,
}
impl BuildPublishCircuitAptosTxn {
    pub fn run(&self) -> Result<()> {
        let mut params_file = std::fs::File::open(self.params_path.as_path())?;
        let params = ParamsKZG::<Bn256>::read(&mut params_file)?;
        let package = load_package(&self.package_dir)?;
        let circuit_name = self.circuit_name.as_deref();
        let circuit_config_args = get_circuit_config_args_from_move_toml(
            &self.package_dir.join("Move.toml"),
            circuit_name,
        )?;

        info!("Loading witness from {:?}", self.witness.display());
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {:?}", self.witness))?;
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &self.pubs_indices,
            circuit_config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());

        let k = best_k(&circuit);
        info!("k = {}", k);
        let mut params = params.clone();
        if k < params.k() {
            params.downsize(k);
        }

        self.build_txn(self.verifier_contract_address.as_str(), circuit, &params)?;
        info!("Transaction built successfully.");

        Ok(())
    }

    fn build_txn(
        &self,
        verifier_contract_address: &str,
        circuit: Rc<VmCircuit<Fr>>,
        params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        let json = build_publish_circuit_transaction_payload(
            params,
            circuit.as_ref(),
            verifier_contract_address,
        )?;

        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-circuit",
            &output,
        )?;

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
        let kzg = match self.variant {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        };
        let proof = std::fs::read(&self.proof_path)
            .with_context(|| format!("Failed to read proof from {:?}", self.proof_path))?;
        let pubs = std::fs::read(&self.pubs_path)
            .with_context(|| format!("Failed to read pubs from {:?}", self.pubs_path))?;
        let public_inputs = PublicInputs::<Fr>::from_bytes(&pubs);
        let json = build_verify_proof_transaction_payload(
            proof,
            kzg as u8,
            public_inputs.as_vec(),
            self.verifier_contract_address.as_str(),
            self.verifier_address.as_str(),
            self.params_address.as_str(),
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
        let mut params_file = std::fs::File::open(self.params_path.as_path())?;
        let params = ParamsKZG::<Bn256>::read(&mut params_file)?;

        let json = build_publish_params_native_transaction_payload(
            &params,
            self.params_contract_address.clone(),
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
        let mut params_file = std::fs::File::open(self.params_path.as_path())?;
        let params = ParamsKZG::<Bn256>::read(&mut params_file)?;
        let package = load_package(&self.package_dir)?;
        let circuit_name = self.circuit_name.as_deref();
        let circuit_config_args = get_circuit_config_args_from_move_toml(
            &self.package_dir.join("Move.toml"),
            circuit_name,
        )?;

        info!("Loading witness from {:?}", self.witness.display());
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {:?}", self.witness))?;
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &self.pubs_indices,
            circuit_config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());

        let k = best_k(&circuit);
        info!("k = {}", k);
        let mut params = params.clone();
        if k < params.k() {
            params.downsize(k);
        }

        let (vk, _pk) = setup_circuit(&*circuit, &params)
            .map_err(|e| anyhow::anyhow!("Failed to setup circuit: {:?}", e))?;

        self.build_vk_txn(&vk)?;
        self.build_circuit_txn(circuit, &params)?;
        info!("Transactions built successfully.");

        Ok(())
    }

    fn build_vk_txn(&self, vk: &VerifyingKey<G1Affine>) -> Result<()> {
        let json = build_publish_vk_native_transaction_payload(
            vk,
            self.native_verifier_contract_address.clone(),
        )?;
        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-vk-native",
            &output,
        )?;
        Ok(())
    }

    fn build_circuit_txn(
        &self,
        circuit: Rc<VmCircuit<Fr>>,
        params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        let json = build_publish_circuit_native_transaction_payload(
            params,
            circuit.as_ref(),
            self.native_verifier_contract_address.clone(),
        )?;

        let output = serde_json::to_string_pretty(&json)?;
        save_txn_output(
            self.output_dir.clone(),
            &self.witness,
            "publish-circuit-native",
            &output,
        )?;

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
            self.native_verifier_contract_address.as_str(),
            self.native_verifier_address.as_str(),
            self.params_address.as_str(),
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
