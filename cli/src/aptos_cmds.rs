use crate::aptos_utils::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes};
use anyhow::{Context, Result};
use circuit::proofs::{best_k, KZG};
use circuit::public_inputs::PublicInputs;
use circuit::vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use clap::{value_parser, Parser, Subcommand, ValueEnum};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use log::debug;
use move_package::{
    compilation::{
        compiled_package::{CompiledPackage, OnDiskCompiledPackage},
        package_layout::CompiledPackageLayout,
    },
    source_package::layout::SourcePackageLayout,
};
use serde_json::json;
use shape_generator::generate_circuit_info;
use std::{
    env::current_dir,
    path::{Path, PathBuf},
    rc::Rc,
};
use toml::Value;
use witnesses::static_info::Footprints;

/// the consts correspond to the definition of vk_registry.move
pub const VK_REGISTRY_MODULE: &str = "vk_registry";
pub const VK_REGISTRY_FUNC: &str = "register_module"; //todo: change to register_vk

/// the consts correspond to the definition of verification network contract.
pub const VERIFICATION_MODULE: &str = "verification";
pub const VERIFICATION_FUNC: &str = "submit_attestation";

/// the consts correspond to the definition of on-chain verifier.
pub const VERIFIER_API: &str = "verifier_api";
pub const PUBLISH_CIRCUIT: &str = "publish_circuit";
pub const VERIFY: &str = "verify_proof";

#[derive(Parser)]
#[command(about = "Generate aptos txns for verify proof on aptos")]
pub struct AptosCommands {
    #[arg(long = "zkmove-address")]
    zkmove_address: String,
    #[arg(long = "package_dir", short = 'p', value_parser = value_parser!(PathBuf))]
    package_dir: PathBuf,
    #[arg(short = 'd', long = "debug", help = "debug mode")]
    debug: bool,
    #[command(subcommand)]
    command: AptosSubcommands,
}
impl AptosCommands {
    pub fn run(&self, params: &ParamsKZG<Bn256>) -> Result<()> {
        let package = self.load_package(&self.package_dir)?;
        let circuit_config_args =
            Self::get_circuit_config_args_from_move_toml(&self.package_dir.join("Move.toml"));

        match &self.command {
            AptosSubcommands::BuildPublishCircuitAptosTxn(cmd) => {
                cmd.run(&package, circuit_config_args, &self.zkmove_address, params)
            }
            AptosSubcommands::BuildVerifyProofAptosTxn(cmd) => cmd.run(&self.zkmove_address),
            AptosSubcommands::BuildRegisterVkAptosTxn(cmd) => {
                cmd.run(&package, &self.zkmove_address, params)
            }
            AptosSubcommands::BuildSubmitAttestationAptosTxn(cmd) => {
                cmd.run(&package, &self.zkmove_address, params)
            }
        }
    }

    fn load_package(&self, rooted_path: &Path) -> Result<CompiledPackage> {
        let manifest_path = rooted_path.join(SourcePackageLayout::Manifest.path());
        let manifest_string = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("Failed to read manifest at {:?}", manifest_path))?;
        let toml_manifest =
            move_package::source_package::manifest_parser::parse_move_manifest_string(
                manifest_string,
            )?;
        let manifest =
            move_package::source_package::manifest_parser::parse_source_manifest(toml_manifest)?;

        let package_name = manifest.package.name.to_string();
        let build_path = rooted_path
            .join(CompiledPackageLayout::Root.path())
            .join(&package_name);
        let package = OnDiskCompiledPackage::from_path(build_path.as_path())
            .with_context(|| format!("Failed to load package at {:?}", build_path))?;
        Ok(package.into_compiled_package()?)
    }

    fn get_circuit_config_args_from_move_toml(toml_path: &Path) -> CircuitConfigArgs {
        let toml_content = std::fs::read_to_string(toml_path).expect("Failed to read Move.toml");
        let parsed_toml: Value = toml_content
            .parse::<Value>()
            .expect("Failed to parse Move.toml");

        if let Some(circuit) = parsed_toml.get("circuit") {
            let max_execution_rows = circuit
                .get("max_execution_rows")
                .and_then(|max_execution_rows| max_execution_rows.as_integer())
                .map(|v| v as usize);

            let max_poseidon_rows = circuit
                .get("max_poseidon_rows")
                .and_then(|max_poseidon_rows| max_poseidon_rows.as_integer())
                .map(|v| v as usize)
                .unwrap_or(0);

            CircuitConfigArgs {
                max_execution_rows,
                max_poseidon_rows,
            }
        } else {
            CircuitConfigArgs::default()
        }
    }
}

#[derive(Subcommand)]
enum AptosSubcommands {
    BuildPublishCircuitAptosTxn(BuildPublishCircuitAptosTxn),
    BuildVerifyProofAptosTxn(BuildVerifyProofTxn),
    BuildRegisterVkAptosTxn(BuildRegisterVkAptosTxn),
    BuildSubmitAttestationAptosTxn(BuildSubmitAttestationTxn),
}

#[derive(Parser)]
struct BuildPublishCircuitAptosTxn {
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
    pub fn run(
        &self,
        package: &CompiledPackage,
        circuit_config_args: CircuitConfigArgs,
        zkmove_address: &str,
        params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        debug!("Loading witness from {:?}", self.witness.display());
        let traces = Footprints::load(&self.witness)
            .with_context(|| format!("Failed to load witness from {:?}", self.witness))?;
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            package,
            &traces,
            &self.pubs_indices,
            circuit_config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());

        let k = best_k(&circuit);
        debug!("k = {}", k);
        let mut params = params.clone();
        if k < params.k() {
            params.downsize(k);
        }

        self.build_txn(zkmove_address, circuit, &params)?;
        Ok(())
    }

    fn save_to_file<P: AsRef<Path>, D: AsRef<[u8]>>(
        &self,
        dir: P,
        file_name: &str,
        data: D,
    ) -> Result<()> {
        let file_path = dir.as_ref().join(file_name);
        std::fs::write(&file_path, data)
            .with_context(|| format!("Failed to save file to {:?}", file_path))?;
        debug!("File saved to {:?}", file_path.display());
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

        self.save_to_file(
            &output_dir,
            &format!("{}-publish-circuit.txn", file_stem),
            &output,
        )?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KZGVariant {
    GWC,
    SHPLONK,
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

        self.save_to_file(
            &output_dir,
            &format!("{}-verify-proof.txn", file_stem),
            &output,
        )?;
        Ok(())
    }

    fn save_to_file<P: AsRef<Path>, D: AsRef<[u8]>>(
        &self,
        dir: P,
        file_name: &str,
        data: D,
    ) -> Result<()> {
        let file_path = dir.as_ref().join(file_name);
        std::fs::write(&file_path, data)
            .with_context(|| format!("Failed to save file to {:?}", file_path))?;
        debug!("File saved to {:?}", file_path.display());
        Ok(())
    }
}

#[derive(Parser)]
struct BuildRegisterVkAptosTxn {
    #[arg(long, default_value = VK_REGISTRY_MODULE)]
    vk_registry_module: String,
    #[arg(long, default_value = VK_REGISTRY_FUNC)]
    vk_registry_func: String,
}
impl BuildRegisterVkAptosTxn {
    pub fn run(
        &self,
        _package: &CompiledPackage,
        _zkmove_address: &str,
        _params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        // TODO
        Ok(())
    }
}

#[derive(Parser)]
struct BuildSubmitAttestationTxn {
    #[arg(long, default_value = VERIFICATION_MODULE)]
    verification_module: String,
    #[arg(long, default_value = VERIFICATION_FUNC)]
    verification_func: String,
}

impl BuildSubmitAttestationTxn {
    pub fn run(
        &self,
        _package: &CompiledPackage,
        _zkmove_address: &str,
        _params: &ParamsKZG<Bn256>,
    ) -> Result<()> {
        // TODO
        Ok(())
    }
}
