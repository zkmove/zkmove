use crate::get_circuit_config_args_from_move_toml;
use crate::load_package;
use crate::save_to_file;
use crate::KZGVariant;
use crate::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes};
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{best_k, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::info;
use serde_json::json;
use shape_generator::generate_circuit_info;
use std::path::PathBuf;
use std::{env::current_dir, rc::Rc};
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitGuard, VmCircuit};
use witness::static_info::Footprints;

/// the consts correspond to the definition of on-chain verifier.
pub const VERIFIER_API: &str = "verifier_api";
pub const PUBLISH_CIRCUIT: &str = "publish_circuit";
pub const VERIFY: &str = "verify_proof";

#[derive(Parser)]
#[command(about = "Generate aptos txns for verify proof on aptos")]
pub struct AptosCommands {
    #[arg(long = "zkmove-address")]
    zkmove_address: String,
    #[arg(short = 'd', long = "debug", help = "debug mode")]
    debug: bool,
    #[command(subcommand)]
    command: AptosSubcommands,
}
impl AptosCommands {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            AptosSubcommands::BuildPublishCircuitAptosTxn(cmd) => cmd.run(&self.zkmove_address),
            AptosSubcommands::BuildVerifyProofAptosTxn(cmd) => cmd.run(&self.zkmove_address),
        }
    }
}

#[derive(Subcommand)]
enum AptosSubcommands {
    BuildPublishCircuitAptosTxn(BuildPublishCircuitAptosTxn),
    BuildVerifyProofAptosTxn(BuildVerifyProofTxn),
}

#[derive(Parser)]
struct BuildPublishCircuitAptosTxn {
    #[arg(long, help = "param file used for prove/verify in kzg")]
    param_path: PathBuf,
    #[arg(long = "package-dir", short = 'p', value_parser = value_parser!(PathBuf))]
    package_dir: PathBuf,
    #[arg(
        long = "circuit-name",
        short = 'c',
        help = "Name of the circuit section in Move.toml (e.g. fibonacci for [circuit.fibonacci]). If omitted, uses the plain [circuit] section in Move.toml."
    )]
    circuit_name: Option<String>,
    #[arg(long = "verifier-module", default_value = VERIFIER_API)]
    onchain_verifier_module: String,
    #[arg(long = "publish-vk-func", default_value = PUBLISH_CIRCUIT)]
    onchain_publish_circuit_func: String,
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
    pub fn run(&self, zkmove_address: &str) -> Result<()> {
        let mut param_file = std::fs::File::open(self.param_path.as_path())?;
        let params = ParamsKZG::<Bn256>::read(&mut param_file)?;
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

        self.build_txn(zkmove_address, circuit, &params)?;
        info!("Build transaction successfully.");

        Ok(())
    }

    fn build_txn(
        &self,
        zkmove_address: &str,
        circuit: Rc<VmCircuit<Fr>>,
        params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        let circuit_info =
            generate_circuit_info(params, &*circuit).expect("Failed to generate circuit info");
        let data = circuit_info
            .serialize()
            .expect("Failed to serialize circuit info");
        let args: Vec<_> = data
            .into_iter()
            .map(|arg| ArgWithTypeJSON {
                r#type: "hex".to_string(),
                value: json!(arg
                    .into_iter()
                    .map(|i| HexEncodedBytes(i).to_string())
                    .collect::<Vec<_>>()),
            })
            .collect();
        let json = EntryFunctionArgumentsJSON {
            function_id: format!(
                "{}::{}::{}",
                zkmove_address, self.onchain_verifier_module, self.onchain_publish_circuit_func
            ),
            type_args: vec![],
            args,
        };
        let output = serde_json::to_string_pretty(&json)?;
        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| current_dir().unwrap());
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create output directory at {:?}", output_dir))?;

        let file_stem = self
            .witness
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid witness file name"))?;

        save_to_file(
            &output_dir,
            &format!("{}-publish-circuit.txn", file_stem),
            &output,
        )?;

        Ok(())
    }
}

#[derive(Parser)]
struct BuildVerifyProofTxn {
    #[arg(long = "verifier-module", default_value = VERIFIER_API)]
    onchain_verifier_module: String,
    #[arg(long, default_value = VERIFY)]
    onchain_verify_func: String,
    #[arg(long = "pubs-path", value_parser = value_parser!(PathBuf))]
    pubs_path: PathBuf,
    #[arg(long = "proof-path", short = 'p', value_parser = value_parser!(PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser!(PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long)]
    param_address: String,
    #[arg(long)]
    circuit_address: String,
    #[arg(long = "kzg", value_enum, default_value_t = KZGVariant::GWC)]
    variant: KZGVariant,
}
impl BuildVerifyProofTxn {
    pub fn run(&self, zkmove_address: &str) -> Result<()> {
        let kzg = match self.variant {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        };
        let proof = std::fs::read(&self.proof_path)
            .with_context(|| format!("Failed to read proof from {:?}", self.proof_path))?;
        let pubs = std::fs::read(&self.pubs_path)
            .with_context(|| format!("Failed to read pubs from {:?}", self.pubs_path))?;
        let public_inputs = PublicInputs::<Fr>::from_bytes(&pubs);
        let json = EntryFunctionArgumentsJSON {
            function_id: format!(
                "{}::{}::{}",
                zkmove_address, self.onchain_verifier_module, self.onchain_verify_func
            ),
            type_args: vec![],
            args: vec![
                ArgWithTypeJSON {
                    r#type: "address".to_string(),
                    value: json!(self.param_address),
                },
                ArgWithTypeJSON {
                    r#type: "address".to_string(),
                    value: json!(self.circuit_address),
                },
                ArgWithTypeJSON {
                    r#type: "hex".to_string(),
                    value: json!(public_inputs
                        .as_vec()
                        .into_iter()
                        .map(|is| is
                            .iter()
                            .map(|fr| fr.to_bytes().to_vec())
                            .map(|d| HexEncodedBytes(d).to_string())
                            .collect::<Vec<_>>())
                        .collect::<Vec<_>>()),
                },
                ArgWithTypeJSON {
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(proof.clone()).to_string()),
                },
                ArgWithTypeJSON {
                    r#type: "u8".to_string(),
                    value: json!(kzg.to_u8()),
                },
            ],
        };

        let output = serde_json::to_string_pretty(&json)?;
        let output_dir = self
            .output_dir
            .clone()
            .unwrap_or_else(|| current_dir().unwrap());
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create output directory at {:?}", output_dir))?;

        let file_stem = self
            .proof_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid proof file name"))?;

        save_to_file(
            &output_dir,
            &format!("{}-verify-proof.txn", file_stem),
            &output,
        )?;
        info!("Build transaction successfully.");
        Ok(())
    }
}
