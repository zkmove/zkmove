use circuit_info_generator::serialize::serialize;
use circuit_info_generator::{generate_circuit_info, CircuitInfo};
use error::VmResult;
use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::ipa::commitment::ParamsIPA;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::{parse_transaction_argument, ScriptArgument, ScriptArguments};
use movelang::compiler::compile_source_files;
use movelang::generic_call_graph::{generate, RemoteStore};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env::current_dir;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use structopt::StructOpt;
use vm::runtime::Runtime;
use vm::state::StateStore;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;
use vm_circuit::{
    find_best_k, mock_prove_circuit, print_circuit_layout, prove_vm_circuit_ipa,
    prove_vm_circuit_kzg, setup_vm_circuit,
};

#[derive(StructOpt)]
#[structopt(name = "zkmove", about = "CLI for zkMove Virtual Machine")]
pub struct Arguments {
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(
        name = "run",
        about = "Run the full sequence of circuit building, setup, proving, and verifying."
    )]
    Run {
        #[structopt(
            short = "s",
            long = "script-file",
            help = "path to .move file containing script"
        )]
        script: PathBuf,

        #[structopt(
            short = "m",
            long = "module-dir",
            help = "directory containing modules"
        )]
        modules: Option<PathBuf>,

        #[structopt(short = "v", long = "verbose")]
        verbose: bool,

        #[structopt(long = "param-path", help = "param file path used for kzg")]
        param_path: PathBuf,

        #[structopt(long, help = "output dir to write protocol and proof to")]
        output_dir: Option<PathBuf>,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn run_kzg(
    script: &Path,
    module_dir: &Option<PathBuf>,
    params: &mut ParamsKZG<Bn256>,
) -> VmResult<(
    VerifyingKey<G1Affine>,
    CircuitInfo<G1Affine>,
    Vec<Fr>,
    Vec<u8>,
)> {
    let script_file = script.to_str().expect("path is None.");

    // compile script and depended modules
    let mut targets = vec![script_file.to_string()];
    let config = RunConfig::new(script)?;

    for module in config.modules.into_iter() {
        let path = module_dir
            .clone()
            .expect("module_dir is missing")
            .as_path()
            .join(module)
            .to_str()
            .unwrap()
            .to_string();
        targets.push(path);
    }
    info!("compile script...{:?}", targets);
    let (compiled_script, compiled_modules) = compile_source_files(targets)?;

    let script = compiled_script.expect("script is missing");
    let runtime = Runtime::<Fr>::new()
        .ext_web3("https://cloudflare-eth.com")
        .unwrap();
    let mut state = StateStore::new();
    for module in compiled_modules.clone().into_iter() {
        state.add_module(module);
    }

    info!("generate execution trace...");
    let circuit_config = CircuitConfig::default()
        .max_step_row(config.step_max_row)
        .stack_ops_num(config.stack_ops_num)
        .locals_ops_num(config.locals_ops_num)
        .global_ops_num(config.global_ops_num)
        .word_size(config.word_capacity);
    let trace = runtime.execute_script(
        script.clone(),
        config.ty_args.clone(),
        config.signer.clone(),
        config.args,
        &mut state,
    )?;
    let witness = runtime.process_execution_trace(
        config.ty_args.clone(),
        Some(script.clone()),
        None,
        compiled_modules.clone(),
        trace,
        circuit_config.clone(),
    )?;

    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
    };
    info!("find the best k...");
    let k = find_best_k(&vm_circuit);
    info!("k = {}", k);
    params.downsize(k);
    // if use_mock {
    //     info!("run with mock prover...");
    //     mock_prove_circuit(&vm_circuit, vec![vec![Fr::zero()]], k)?;
    // }
    //
    // if print_layout {
    //     info!("print circuit layout into layout.svg ...");
    //     print_circuit_layout(k, &vm_circuit);
    // }

    info!("setup vm circuit...");
    let (vk, pk) = setup_vm_circuit(&vm_circuit, params)?;
    let circuit_info = generate_circuit_info(params, &vm_circuit).unwrap();
    info!("prove vm circuit...");
    let proof = prove_vm_circuit_kzg(vm_circuit, &[&[Fr::zero()]], params, pk.clone())?;
    Ok((vk, circuit_info, vec![Fr::zero()], proof))
}

fn main() -> anyhow::Result<()> {
    let args: Arguments = Arguments::from_args();

    match args.cmd {
        Command::Run {
            ref script,
            ref modules,
            verbose,
            ref param_path,
            output_dir,
        } => {
            logger::init_for_main(verbose);
            let mut params = {
                let mut param_file =
                    std::fs::File::open(param_path.as_path()).expect("param path is valid");

                let mut params =
                    ParamsKZG::<Bn256>::read(&mut param_file).expect("param file is valid");
                params
            };

            let (vk, circuit_info, instances, proof) =
                run_kzg(script.as_path(), modules, &mut params)?;
            let data = serialize(circuit_info.into())?;

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
            let publish_json = EntryFunctionArgumentsJSON {
                function_id: format!("0x1234::halo2_verifier::publish_vk"),
                type_args: vec![],
                args,
            };

            let instances: Vec<_> = instances.iter().map(|fr| fr.to_bytes().to_vec()).collect();
            let verify_json = EntryFunctionArgumentsJSON {
                function_id: format!("0x1234::halo2_verifier::verify"),
                type_args: vec![],
                args: vec![
                    ArgWithTypeJSON {
                        arg_type: "hex".to_string(),
                        value: json!(HexEncodedBytes(proof.clone()).to_string()),
                    },
                    ArgWithTypeJSON {
                        arg_type: "hex".to_string(),
                        value: json!(instances
                            .into_iter()
                            .map(|i| HexEncodedBytes(i).to_string())
                            .collect::<Vec<_>>()),
                    },
                ],
            };

            let output_path = output_dir.unwrap_or_else(|| current_dir().unwrap());
            std::fs::create_dir_all(output_path.as_path())?;
            std::fs::write(
                output_path
                    .join(format!(
                        "{}.publish-protocol",
                        script.file_name().unwrap().to_string_lossy()
                    ))
                    .with_extension("json"),
                serde_json::to_string_pretty(&publish_json)?,
            )?;
            std::fs::write(
                output_path
                    .join(format!(
                        "{}.verify-proof",
                        script.file_name().unwrap().to_string_lossy()
                    ))
                    .with_extension("json"),
                serde_json::to_string_pretty(&verify_json)?,
            )?;
            Ok(())
        }
    }
}

#[derive(Deserialize, Serialize)]
/// JSON file format for function arguments.
pub struct ArgWithTypeJSON {
    #[serde(rename = "type")]
    pub(crate) arg_type: String,
    pub(crate) value: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
/// JSON file format for entry function arguments.
pub struct EntryFunctionArgumentsJSON {
    pub(crate) function_id: String,
    pub(crate) type_args: Vec<String>,
    pub(crate) args: Vec<ArgWithTypeJSON>,
}

/// Hex encoded bytes to allow for having bytes represented in JSON
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl fmt::Display for HexEncodedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))?;
        Ok(())
    }
}
