use crate::KZGVariant;
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{best_k, prove_circuit, setup_circuit, verify_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::keygen_vk,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use log::debug;
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId,
};
use move_package::{
    compilation::{
        compiled_package::{CompiledPackage, OnDiskCompiledPackage},
        package_layout::CompiledPackageLayout,
    },
    source_package::layout::SourcePackageLayout,
};
use std::{
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
};
use toml::Value;
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitConfigArgs, CircuitGuard, VmCircuit};
use witness::static_info::{EntryInfo, Footprints, ModuleIdMapping};

#[derive(Parser)]
#[command(about = "Command for proving and verification in the client side.")]
pub struct VmCommands {
    #[arg(long, help = "Param file used for prove/verify in kzg")]
    param_path: PathBuf,

    #[arg(
        long = "package-path",
        value_parser = value_parser!(PathBuf),
        help = "Path to the Move package root (contains Move.toml)"
    )]
    package_path: PathBuf,

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

    #[arg(short = 'd', long = "debug", help = "Use mock prover for debugging")]
    debug: bool,

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save proof/verification artifacts (default: <package-path>/proofs)"
    )]
    output_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    #[command(about = "Generate proof based on witness")]
    Prove(ProveCommand),

    #[command(about = "Verify proof")]
    Verify(VerifyCommand),
}

#[derive(Parser)]
#[command(about = "Generate proof based on witness")]
pub struct ProveCommand {
    #[arg(
        short = 'w',
        long = "witness",
        help = "Path to .json file containing witness",
        required = true
    )]
    witness: PathBuf,
}

#[derive(Parser)]
#[command(about = "Verify the proof")]
pub struct VerifyCommand {
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

impl VmCommands {
    pub fn run(&self) -> Result<()> {
        let mut params_file = std::fs::File::open(&self.param_path)?;
        let mut params = ParamsKZG::<Bn256>::read(&mut params_file)?;

        match &self.command {
            Subcommands::Prove(prove) => prove.run(
                &mut params,
                &self.package_path,
                &prove.witness,
                &self.pubs_indices,
                self.variant,
                self.debug,
                self.output_dir.as_deref(),
            ),

            Subcommands::Verify(verify) => verify.run(
                &mut params,
                &self.package_path,
                verify.k,
                &self.pubs_indices,
                self.variant,
                self.debug,
                &verify.proof_path,
                &verify.pubs_path,
            ),
        }
    }
}

impl ProveCommand {
    fn run(
        &self,
        params: &mut ParamsKZG<Bn256>,
        package_path: &Path,
        witness_path: &Path,
        pubs_indices: &[usize],
        variant: KZGVariant,
        _debug: bool,
        output_dir_override: Option<&Path>,
    ) -> Result<()> {
        debug!("Loading witness from: {}", witness_path.display());
        let traces = Footprints::load(witness_path)
            .with_context(|| format!("Failed to load witness from {}", witness_path.display()))?;

        let manifest_path = package_path.join("Move.toml");
        let package = load_package(package_path)?;

        let config_args = get_circuit_config_args_from_move_toml(&manifest_path)?;

        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            pubs_indices,
            config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());

        let k = best_k(&circuit);
        debug!("Optimal k = {}", k);

        // let mut params = params.clone();
        if k < params.k() {
            params.downsize(k);
        }

        let args = traces.args().context("Arguments not found in witness")?;
        let public_inputs = PublicInputs::new(&args, pubs_indices);

        self.generate_and_save_proof(
            circuit,
            &public_inputs,
            params,
            package_path,
            output_dir_override,
            variant,
        )
    }

    fn generate_and_save_proof(
        &self,
        circuit: Rc<VmCircuit<Fr>>,
        public_inputs: &PublicInputs<Fr>,
        params: &ParamsKZG<Bn256>,
        package_path: &Path,
        output_dir_override: Option<&Path>,
        variant: KZGVariant,
    ) -> Result<()> {
        let (vk, pk) = setup_circuit(&*circuit, params).expect("setup should not fail");

        let kzg_scheme = match variant {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        };

        let proof = prove_circuit((*circuit).clone(), public_inputs, params, &pk, kzg_scheme)
            .expect("proof generation should not fail");

        let output_dir = output_dir_override
            .map(PathBuf::from)
            .unwrap_or_else(|| package_path.join("proofs"));

        std::fs::create_dir_all(&output_dir)?;

        let file_stem = self
            .witness
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid witness filename"))?;

        save_to_file(&output_dir, &format!("{}.proof", file_stem), &proof)?;
        save_to_file(
            &output_dir,
            &format!("{}.instance", file_stem),
            public_inputs.to_bytes(),
        )?;
        save_to_file(
            &output_dir,
            &format!("{}.vk", file_stem),
            &vk.to_bytes(SerdeFormat::Processed),
        )?;

        debug!("Proof artifacts saved to: {}", output_dir.display());
        Ok(())
    }
}

impl VerifyCommand {
    fn run(
        &self,
        params: &mut ParamsKZG<Bn256>,
        package_path: &Path,
        k: u32,
        pubs_indices: &[usize],
        variant: KZGVariant,
        _debug: bool,
        proof_path: &Path,
        pubs_path: &Path,
    ) -> Result<()> {
        if k < params.k() {
            params.downsize(k);
        }

        let manifest_path = package_path.join("Move.toml");
        let config_args = get_circuit_config_args_from_move_toml(&manifest_path)?;
        let entry_info = get_entry_info_from_move_toml(&manifest_path)?;

        let package = load_package(package_path)?;

        let circuit = Rc::new(VmCircuit::<Fr>::new_with_empty_state(
            &package,
            entry_info,
            pubs_indices,
            config_args,
        ));

        let _circuit_guard = CircuitGuard::new(circuit.clone());
        // must be called after CircuitGuard, because vk depends on the circuit config
        let vk =
            keygen_vk::<_, _, VmCircuit<Fr>>(params, &circuit).expect("keygen_vk should not fail");

        let proof = std::fs::read(proof_path)?;
        let pubs_bytes = std::fs::read(pubs_path)?;
        let public_inputs = PublicInputs::from_bytes(&pubs_bytes);

        let kzg_scheme = match variant {
            KZGVariant::GWC => KZG::GWC,
            KZGVariant::SHPLONK => KZG::SHPLONK,
        };
        verify_circuit(&public_inputs, &params, &vk, &proof, kzg_scheme)
            .expect("verify proof should be ok");

        debug!("Proof verified successfully");
        Ok(())
    }
}

fn find_package_root(witness: &Path) -> Result<PathBuf> {
    SourcePackageLayout::try_find_root(&witness.canonicalize()?)
        .context("Failed to find root path for the package")
}

fn get_circuit_config_args_from_move_toml(toml_path: &Path) -> Result<CircuitConfigArgs> {
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

        Ok(CircuitConfigArgs {
            max_execution_rows,
            max_poseidon_rows,
        })
    } else {
        Ok(CircuitConfigArgs::default())
    }
}

fn get_entry_info_from_move_toml(toml_path: &Path) -> Result<EntryInfo> {
    let toml_content = std::fs::read_to_string(toml_path)?;
    let parsed_toml: Value = toml_content.parse()?;

    let circuit = parsed_toml
        .get("circuit")
        .context("[circuit] section not found in Move.toml")?;

    let entry = circuit
        .get("entry")
        .context("entry not found under [circuit] in Move.toml")?;

    let module_id_str = entry
        .get("module_id")
        .and_then(|v| v.as_str())
        .context("module_id is missing or invalid")?;
    let function_name = entry
        .get("function_name")
        .and_then(|v| v.as_str())
        .context("function_name is missing or invalid")?;

    let module_id = parse_module_id(module_id_str)?;

    let package_root = find_package_root(toml_path)?;
    let package = load_package(&package_root)?;
    let module_id_mapping = ModuleIdMapping::construct(&module_id, &package);

    Ok(EntryInfo::new(
        &package,
        &module_id,
        function_name,
        &module_id_mapping,
    ))
}

fn parse_module_id(module_id_str: &str) -> Result<ModuleId> {
    let parts: Vec<&str> = module_id_str.split("::").collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid module_id format: {}",
            module_id_str
        ));
    }
    let address = AccountAddress::from_str(parts[0])?;
    let name = Identifier::new(parts[1])?;
    Ok(ModuleId::new(address, name.into()))
}

fn load_package(rooted_path: &Path) -> Result<CompiledPackage> {
    let manifest_path = rooted_path.join(SourcePackageLayout::Manifest.path());
    let manifest_string = std::fs::read_to_string(&manifest_path)?;
    let toml_manifest =
        move_package::source_package::manifest_parser::parse_move_manifest_string(manifest_string)?;
    let manifest =
        move_package::source_package::manifest_parser::parse_source_manifest(toml_manifest)?;

    let package_name = manifest.package.name.to_string();
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(&package_name);

    let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
    Ok(package.into_compiled_package()?)
}

fn save_to_file<P: AsRef<Path>, D: AsRef<[u8]>>(dir: P, file_name: &str, data: D) -> Result<()> {
    let file_path = dir.as_ref().join(file_name);
    std::fs::write(&file_path, data)?;
    debug!("File saved to {:?}", file_path.display());
    Ok(())
}
