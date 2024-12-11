use crate::aptos_utils::{ArgWithTypeJSON, EntryFunctionArgumentsJSON, HexEncodedBytes};
use crate::verifier_utils::*;
use anyhow::Result;
use aptos_move_witnesses::static_info::StaticInfo;
use clap::{value_parser, Parser, Subcommand, ValueEnum};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use move_binary_format::access::ModuleAccess;
use move_core_types::{identifier::Identifier, language_storage::ModuleId};
use move_package::{
    compilation::{
        compiled_package::{CompiledPackage, OnDiskCompiledPackage},
        package_layout::CompiledPackageLayout,
    },
    source_package::layout::SourcePackageLayout,
};
use serde_json::json;
use shape_generator::{generate_circuit_info, serialize};
use std::{env::current_dir, fs, path::PathBuf, str::FromStr};
use vm_circuit::{
    circuit_v2::VmCircuit,
    witness::{CircuitConfigV2, WitnessV2},
    SubCircuit, KZG,
};
#[derive(Debug, Clone)]
pub struct ModuleIdWrapper(ModuleId);

impl FromStr for ModuleIdWrapper {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("::").collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid module id format. Expected 'address::name'");
        }
        Ok(ModuleIdWrapper(ModuleId::new(
            parts[0].parse()?,
            Identifier::new(parts[1])?,
        )))
    }
}

#[derive(Parser)]
pub struct AptosCommands {
    #[arg(long = "verifier-address")]
    verifier_address: String,
    #[arg(long = "verifier-module", default_value = VERIFIER_API)]
    verifier_module: String,
    #[arg(long = "publish-vk-func", default_value = PUBLISH_CIRCUIT)]
    publish_vk_func: String,
    #[arg(long, default_value = VERIFY)]
    verify_func: String,
    #[arg(long)]
    param_path: PathBuf,
    #[arg(short)]
    k: u8,
    #[arg(long = "package_dir", short = 'p', value_parser = value_parser ! (PathBuf))]
    package_dir: PathBuf,
    #[arg(short = 'd', long = "debug", help = "debug mode")]
    debug: bool,
    #[command(subcommand)]
    command: AptosSubcommands,
}

#[derive(Subcommand)]
enum AptosSubcommands {
    ViewParam,
    BuildPublishVkAptosTxn(BuildPublishVkAptosTxn),
    BuildVerifyProofAptosTxn(BuildVerifyProofTxn),
}

#[derive(Parser)]
struct BuildPublishVkAptosTxn {
    #[arg(long = "entry_module", value_parser = value_parser!(ModuleIdWrapper))]
    entry_module: ModuleIdWrapper,
    #[arg(long = "function_name", value_parser = value_parser ! (Identifier))]
    function_name: Identifier,
    #[arg(long = "output", short = 'o', value_parser = value_parser ! (PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long = "max_rows", default_value = "1024")]
    max_num_rows: usize,
}
impl BuildPublishVkAptosTxn {
    pub fn run(
        &self,
        package: &CompiledPackage,
        verifier_address: &str,
        verifier_module: &str,
        publish_vk_func: &str,
        params_kzg: ParamsKZG<Bn256>,
    ) -> Result<()> {
        let entry_module = package
            .root_modules_map()
            .get_module(&self.entry_module.0)?
            .clone();
        let function_identifier_index = entry_module
            .identifiers()
            .iter()
            .enumerate()
            .find(|(_i, n)| n.as_str() == self.function_name.as_str())
            .ok_or(anyhow::anyhow!(
                "cannot find function {} in module {}",
                self.function_name.as_str(),
                entry_module.name()
            ))?
            .0;
        let function_index = entry_module
            .function_defs()
            .iter()
            .enumerate()
            .find(|(_i, fd)| {
                entry_module.function_handle_at(fd.function).name.0
                    == function_identifier_index as u16
            })
            .unwrap_or_else(|| panic!("index function {} ok", self.function_name.as_str()));
        let static_info =
            StaticInfo::generate(&self.entry_module.0, function_index.0 as u16, package);
        let witness = WitnessV2::new(vec![], static_info, CircuitConfigV2::new(self.max_num_rows));
        let circuit = VmCircuit::<Fr>::new_from_witness(&witness);
        let circuit_info = generate_circuit_info(&params_kzg, &circuit)?;
        let data = serialize::serialize(circuit_info.into())?;
        let args: Vec<_> = data
            .into_iter()
            .map(|arg| ArgWithTypeJSON {
                arg_type: "hex".to_string(),
                value: json!(arg
                    .into_iter()
                    .map(|i| HexEncodedBytes(i).to_string())
                    .collect::<Vec<_>>()),
            })
            .collect();
        let json = EntryFunctionArgumentsJSON {
            function_id: format!(
                "{}::{}::{}",
                verifier_address, verifier_module, publish_vk_func
            ),
            type_args: vec![],
            args,
        };
        let output = serde_json::to_string_pretty(&json)?;
        let output_path = self
            .output_dir
            .clone()
            .unwrap_or_else(|| current_dir().unwrap());
        std::fs::create_dir_all(output_path.as_path())?;

        std::fs::write(
            output_path
                .join(format!("{:?}-publish-circuit", self.function_name.as_str()))
                .with_extension("json"),
            output,
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KZGVariant {
    GWC,
    SHPLONK,
}
impl From<KZGVariant> for KZG {
    fn from(value: KZGVariant) -> Self {
        match value {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        }
    }
}

#[derive(Parser)]
struct BuildVerifyProofTxn {
    #[arg(long = "proof", short = 'p', value_parser = value_parser ! (PathBuf))]
    proof_path: PathBuf,
    #[arg(long = "output", short = 'o', value_parser = value_parser ! (PathBuf))]
    output_dir: Option<PathBuf>,
    #[arg(long)]
    param_address: String,
    #[arg(long)]
    circuit_address: String,

    #[arg(long = "kzg", value_enum)]
    variant: KZGVariant,
}
impl BuildVerifyProofTxn {
    pub fn run(
        &self,
        verifier_address: &str,
        verifier_module: &str,
        verify_func: &str,
    ) -> Result<()> {
        let proof = fs::read(self.proof_path.as_path())?;
        // TODO: zkmove have no instance for now
        let instances: Vec<Vec<Fr>> = vec![];
        let json = EntryFunctionArgumentsJSON {
            function_id: format!("{}::{}::{}", verifier_address, verifier_module, verify_func),
            type_args: vec![],
            args: vec![
                ArgWithTypeJSON {
                    arg_type: "address".to_string(),
                    value: json!(self.param_address),
                },
                ArgWithTypeJSON {
                    arg_type: "address".to_string(),
                    value: json!(self.circuit_address),
                },
                ArgWithTypeJSON {
                    arg_type: "hex".to_string(),
                    value: json!(instances
                        .into_iter()
                        .map(|is| is
                            .iter()
                            .map(|fr| fr.to_bytes().to_vec())
                            .map(|d| HexEncodedBytes(d).to_string())
                            .collect::<Vec<_>>())
                        .collect::<Vec<_>>()),
                },
                ArgWithTypeJSON {
                    arg_type: "hex".to_string(),
                    value: json!(HexEncodedBytes(proof.clone()).to_string()),
                },
                ArgWithTypeJSON {
                    arg_type: "u8".to_string(),
                    value: json!(KZG::from(self.variant).to_u8()),
                },
            ],
        };

        let output = serde_json::to_string_pretty(&json)?;
        let output_path = self
            .output_dir
            .clone()
            .unwrap_or_else(|| current_dir().unwrap());
        fs::create_dir_all(output_path.as_path())?;

        fs::write(
            output_path
                .join(format!(
                    "{:?}-verify-txn",
                    self.proof_path.file_stem().unwrap(),
                ))
                .with_extension("json"),
            output,
        )?;
        Ok(())
    }
}

impl AptosCommands {
    pub fn run(&self) -> Result<()> {
        // Always root ourselves to the package root, and then compile relative to that.
        let rooted_path = SourcePackageLayout::try_find_root(&self.package_dir.canonicalize()?)?;
        let manifest = {
            let manifest_string =
                std::fs::read_to_string(rooted_path.join(SourcePackageLayout::Manifest.path()))?;
            let toml_manifest =
                move_package::source_package::manifest_parser::parse_move_manifest_string(
                    manifest_string,
                )?;
            move_package::source_package::manifest_parser::parse_source_manifest(toml_manifest)?
        };

        let package_name = manifest.package.name.to_string();
        let build_path = rooted_path
            .join(CompiledPackageLayout::Root.path())
            .join(&package_name);
        let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
        let package = package.into_compiled_package()?;

        let params = if self.debug {
            let rng = rand::rngs::mock::StepRng::new(0, 1);
            ParamsKZG::<Bn256>::setup(self.k as u32, rng)
        } else {
            let rng = rand::thread_rng();
            ParamsKZG::<Bn256>::setup(self.k as u32, rng)
        };

        match &self.command {
            AptosSubcommands::ViewParam => {
                // TODO: Implement view param logic
                Ok(())
            }
            AptosSubcommands::BuildPublishVkAptosTxn(cmd) => cmd.run(
                &package,
                &self.verifier_address,
                &self.verifier_module,
                &self.publish_vk_func,
                params,
            ),
            AptosSubcommands::BuildVerifyProofAptosTxn(cmd) => cmd.run(
                &self.verifier_address,
                &self.verifier_module,
                &self.verify_func,
            ),
        }
    }
}
