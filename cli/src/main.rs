use error::VmResult;
use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::ipa::commitment::ParamsIPA;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::{parse_transaction_argument, ScriptArgument, ScriptArguments};
use movelang::compiler::compile_source_files;
use movelang::generic_call_graph::{generate, RemoteStore};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;
use structopt::StructOpt;
use vm::runtime::Runtime;
use vm::state::StateStore;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;

use rand::{rngs::StdRng, SeedableRng};
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

        #[structopt(short = "d", long = "debug", help = "debug with mock prover")]
        use_mock: bool,

        #[structopt(
            long = "new-args",
            help = "run with new arguments, still use the old proving/verifying keys, multiple args should separate with space",
            parse(try_from_str = parse_transaction_argument)
        )]
        new_args: Option<Vec<ScriptArgument>>,

        #[structopt(short = "v", long = "verbose")]
        verbose: bool,

        #[structopt(long = "print-layout")]
        print_layout: bool,
        #[structopt(long = "pcs", help = "polynomial commitment scheme")]
        pcs: Option<Pcs>,

        #[structopt(long = "param-path", help = "param file path used for kzg")]
        param_path: Option<PathBuf>,
    },
    #[structopt(name = "graph", about = "generate generic call graph")]
    CallGraph { module: PathBuf, output: PathBuf },
}

#[derive(Copy, Clone, Debug)]
pub enum Pcs {
    KZG,
    IPA,
}
impl FromStr for Pcs {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "kzg" => Self::KZG,
            "ipa" => Self::IPA,
            _ => return Err(format!("can parse string {} to PCS", s)),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_kzg(
    script: &Path,
    module_dir: &Option<PathBuf>,
    use_mock: bool,
    new_args: &Option<Vec<ScriptArgument>>,
    print_layout: bool,
    param_path: Option<PathBuf>,
) -> VmResult<()> {
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

    if use_mock {
        info!("run with mock prover...");
        mock_prove_circuit(&vm_circuit, vec![vec![Fr::zero()]], k)?;
    }

    if print_layout {
        info!("print circuit layout into layout.svg ...");
        print_circuit_layout(k, &vm_circuit);
    }

    info!("setup vm circuit...");
    let params = if let Some(param_path) = param_path {
        let mut param_file =
            std::fs::File::open(param_path.as_path()).expect("param path is valid");

        let mut params = ParamsKZG::<Bn256>::read(&mut param_file).expect("param file is valid");

        params.downsize(k as u32);
        params
    } else {
        let rng = StdRng::from_entropy();
        ParamsKZG::<Bn256>::setup(k, rng)
    };

    let (_, pk) = setup_vm_circuit(&vm_circuit, &params)?;

    info!("prove vm circuit...");
    prove_vm_circuit_kzg(vm_circuit, &[&[Fr::zero()]], &params, pk.clone())?;
    #[allow(clippy::or_fun_call)]
    if let Some(new_args) = new_args
        .as_ref()
        .or(config.new_args.as_ref().map(|t| t.as_inner()))
    {
        info!("execute script with new arguments");
        let arguments = Some(ScriptArguments::new(new_args.clone()));
        let new_ty_args = if config.new_ty_args.is_empty() {
            config.ty_args
        } else {
            config.new_ty_args
        };
        let new_trace = runtime.execute_script(
            script.clone(),
            new_ty_args.clone(),
            config.signer,
            arguments,
            &mut state,
        )?;
        let new_witness = runtime.process_execution_trace(
            new_ty_args,
            Some(script),
            None,
            compiled_modules,
            new_trace,
            circuit_config,
        )?;
        let new_vm_circuit = VmCircuit {
            witness: new_witness,
            public_input: None,
        };
        info!("prove the new execution with old proving key...");
        prove_vm_circuit_kzg(new_vm_circuit, &[&[Fr::zero()]], &params, pk)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_ipa(
    script: &Path,
    module_dir: &Option<PathBuf>,
    use_mock: bool,
    new_args: &Option<Vec<ScriptArgument>>,
    print_layout: bool,
) -> VmResult<()> {
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
    info!("compile script...");
    let (compiled_script, compiled_modules) = compile_source_files(targets)?;

    let script = compiled_script.expect("script is missing");
    let runtime = Runtime::<Fp>::new();
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

    if use_mock {
        info!("run with mock prover...");
        mock_prove_circuit(&vm_circuit, vec![vec![Fp::zero()]], k)?;
    }

    if print_layout {
        info!("print circuit layout into layout.svg ...");
        print_circuit_layout(k, &vm_circuit);
    }

    info!("setup vm circuit...");
    let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
    let (_, pk) = setup_vm_circuit(&vm_circuit, &params)?;

    info!("prove vm circuit...");
    prove_vm_circuit_ipa(vm_circuit, &[&[Fp::zero()]], &params, pk.clone())?;
    #[allow(clippy::or_fun_call)]
    if let Some(new_args) = new_args
        .as_ref()
        .or(config.new_args.as_ref().map(|t| t.as_inner()))
    {
        info!("execute script with new arguments");
        let arguments = Some(ScriptArguments::new(new_args.clone()));
        let new_ty_args = if config.new_ty_args.is_empty() {
            config.ty_args
        } else {
            config.new_ty_args
        };
        let new_trace = runtime.execute_script(
            script.clone(),
            new_ty_args.clone(),
            config.signer,
            arguments,
            &mut state,
        )?;

        let new_witness = runtime.process_execution_trace(
            new_ty_args,
            Some(script),
            None,
            compiled_modules,
            new_trace,
            circuit_config,
        )?;
        let new_vm_circuit = VmCircuit {
            witness: new_witness,
            public_input: None,
        };
        info!("prove the new execution with old proving key...");
        prove_vm_circuit_ipa(new_vm_circuit, &[&[Fp::zero()]], &params, pk)?;
    }

    Ok(())
}

fn main() {
    let args: Arguments = Arguments::from_args();

    let result = match args.cmd {
        Command::Run {
            ref script,
            ref modules,
            use_mock,
            ref new_args,
            verbose,
            print_layout,
            pcs,
            ref param_path,
        } => {
            logger::init_for_main(verbose);
            match pcs {
                Some(Pcs::IPA) => run_ipa(script, modules, use_mock, new_args, print_layout),
                Some(Pcs::KZG) | None => run_kzg(
                    script,
                    modules,
                    use_mock,
                    new_args,
                    print_layout,
                    param_path.clone(),
                ),
            }
        }
        Command::CallGraph { module, output } => {
            std::fs::create_dir_all(output.as_path()).unwrap();
            let module =
                CompiledModule::deserialize(std::fs::read(module.as_path()).unwrap().as_ref())
                    .unwrap();
            let store = {
                let mut s = RemoteStore::default();
                s.add_module(&module);
                s
            };
            let graphs = generate(&module.self_id(), &store);
            for (fname, graph) in graphs {
                std::fs::write(output.join(fname).with_extension("dot"), graph.to_dot()).unwrap();
            }
            Ok(())
        }
    };

    if let Err(error) = result {
        error!("{}", error);
        exit(1);
    }
}
