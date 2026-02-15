use crate::{
    get_circuit_config_args_from_move_toml, get_entry_info_from_move_toml, load_package,
    save_to_file, ArgWithNameAndTypeJSON, HexEncodedBytes, KZGVariant,
};
use anyhow::{Context, Result};
use clap::{value_parser, Parser, Subcommand};
use halo2::proofs::{best_k, prove_circuit, setup_circuit, verify_circuit, KZG};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::keygen_vk,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use halo2_verifier::{test_verifier, KZG as VerifierKZG};
use log::debug;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    rc::Rc,
};
use vm_circuit::public_inputs::PublicInputs;
use vm_circuit::{CircuitGuard, VmCircuit};
use witness::static_info::Footprints;

#[derive(Parser)]
#[command(about = "Command for proving and verification in the client side.")]
pub struct VmCommands {
    #[arg(long, help = "Params file used for prove/verify in kzg")]
    params_path: PathBuf,

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

    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    #[command(about = "Generate proof based on witness")]
    Prove(ProveCommand),

    #[command(about = "Verify proof")]
    Verify(VerifyCommand),

    #[command(about = "Test the on-chain verifier on provided witness files")]
    Test(TestCommand),
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

    #[arg(
        short = 'o',
        long = "output-dir",
        help = "Directory to save proof/verification artifacts (default: <package-path>/proofs)"
    )]
    output_dir: Option<PathBuf>,

    #[arg(
        long = "json",
        help = "Whether the witness file is in JSON format (default: binary format)",
        default_value_t = false
    )]
    json: bool,
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

#[derive(Parser)]
#[command(about = "Test the on-chain verifier on provided witness files")]
pub struct TestCommand {
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
        help = "Whether the witness file is in JSON format (default: binary format)",
        default_value_t = false
    )]
    json: bool,
}

impl VmCommands {
    pub fn run(&self) -> Result<()> {
        let mut params_file = std::fs::File::open(&self.params_path)?;
        let mut params = ParamsKZG::<Bn256>::read(&mut params_file)?;

        match &self.command {
            Subcommands::Prove(prove) => prove.run(
                &mut params,
                &self.package_path,
                self.circuit_name.as_deref(),
                &prove.witness,
                &self.pubs_indices,
                self.variant,
                self.debug,
                prove.output_dir.as_deref(),
                prove.json,
            ),

            Subcommands::Verify(verify) => verify.run(
                &mut params,
                &self.package_path,
                self.circuit_name.as_deref(),
                verify.k,
                &self.pubs_indices,
                self.variant,
                self.debug,
                &verify.proof_path,
                &verify.pubs_path,
            ),
            Subcommands::Test(test) => test.run(
                &mut params,
                &self.package_path,
                self.circuit_name.as_deref(),
                &test.witness,
                &self.pubs_indices,
                self.variant,
                self.debug,
                test.output_dir.as_deref(),
                test.json,
            ),
        }
    }
}

impl ProveCommand {
    fn run(
        &self,
        params: &mut ParamsKZG<Bn256>,
        package_path: &Path,
        circuit_name: Option<&str>,
        witness_path: &Path,
        pubs_indices: &[usize],
        variant: KZGVariant,
        _debug: bool,
        output_dir_override: Option<&Path>,
        json: bool,
    ) -> Result<()> {
        debug!("Loading witness from: {}", witness_path.display());
        let traces = Footprints::load(witness_path)
            .with_context(|| format!("Failed to load witness from {}", witness_path.display()))?;

        let manifest_path = package_path.join("Move.toml");
        let package = load_package(package_path)?;

        let config_args = get_circuit_config_args_from_move_toml(&manifest_path, circuit_name)?;

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
            json,
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
        json: bool,
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

        if json {
            let content = vec![
                ArgWithNameAndTypeJSON {
                    name: "public_inputs".to_string(),
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
                ArgWithNameAndTypeJSON {
                    name: "proof".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(proof).to_string()),
                },
                ArgWithNameAndTypeJSON {
                    name: "vk".to_string(),
                    r#type: "hex".to_string(),
                    value: json!(HexEncodedBytes(vk.to_bytes(SerdeFormat::Processed)).to_string()),
                },
            ];
            let output = serde_json::to_string_pretty(&content)?;
            save_to_file(&output_dir, &format!("{}.json", file_stem), &output)?;
        }

        debug!("Proof artifacts saved to: {}", output_dir.display());
        Ok(())
    }
}

impl VerifyCommand {
    fn run(
        &self,
        params: &mut ParamsKZG<Bn256>,
        package_path: &Path,
        circuit_name: Option<&str>,
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
        let config_args = get_circuit_config_args_from_move_toml(&manifest_path, circuit_name)?;
        let entry_info = get_entry_info_from_move_toml(&manifest_path, circuit_name)?;

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

impl TestCommand {
    fn run(
        &self,
        params: &mut ParamsKZG<Bn256>,
        package_path: &Path,
        circuit_name: Option<&str>,
        witness_path: &Path,
        pubs_indices: &[usize],
        variant: KZGVariant,
        _debug: bool,
        output_dir_override: Option<&Path>,
        _json: bool,
    ) -> Result<()> {
        debug!("Loading witness from: {}", witness_path.display());
        let traces = Footprints::load(witness_path)
            .with_context(|| format!("Failed to load witness from {}", witness_path.display()))?;

        let manifest_path = package_path.join("Move.toml");
        let package = load_package(package_path)?;

        let config_args = get_circuit_config_args_from_move_toml(&manifest_path, circuit_name)?;

        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            pubs_indices,
            config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());

        let k = best_k(&circuit);
        debug!("Optimal k = {}", k);

        if k < params.k() {
            params.downsize(k);
        }

        let args = traces.args().context("Arguments not found in witness")?;
        let public_inputs = PublicInputs::new(&args, pubs_indices);

        self.test_native_verifier(
            circuit,
            &public_inputs,
            params,
            package_path,
            output_dir_override,
            variant,
        )
    }

    fn test_native_verifier(
        &self,
        circuit: Rc<VmCircuit<Fr>>,
        public_inputs: &PublicInputs<Fr>,
        params: &ParamsKZG<Bn256>,
        package_path: &Path,
        output_dir_override: Option<&Path>,
        variant: KZGVariant,
    ) -> Result<()> {
        let (_vk, _pk) = setup_circuit(&*circuit, params).expect("setup should not fail");

        let verifier_kzg_scheme = match variant {
            KZGVariant::GWC => VerifierKZG::GWC,
            KZGVariant::SHPLONK => VerifierKZG::SHPLONK,
        };

        let test_data = test_verifier(
            circuit.as_ref().clone(),
            public_inputs.as_vec(),
            params,
            verifier_kzg_scheme,
        )
        .expect("on-chain verifier test should not fail");

        let output_dir = output_dir_override
            .map(PathBuf::from)
            .unwrap_or_else(|| package_path.join("proofs"));
        std::fs::create_dir_all(&output_dir)?;

        let file_stem = self
            .witness
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid witness filename"))?;

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

        Ok(())
    }
}
