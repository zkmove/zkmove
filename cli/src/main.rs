use error::VmResult;
use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::ipa::commitment::ParamsIPA;
use logger::prelude::*;
use movelang::argument::{parse_transaction_argument, ScriptArgument, ScriptArguments};
use movelang::compiler::compile_script;
use movelang::generic_call_graph::generate;
use movelang::state::StateStore;
use std::path::{Path, PathBuf};
use std::process::exit;
use structopt::StructOpt;
use vm::runtime::Runtime;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;

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
    },
    #[structopt(name = "graph", about = "generate generic call graph")]
    CallGraph { module: PathBuf, output: PathBuf },
}

impl Arguments {
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        script: &Path,
        module_dir: &Option<PathBuf>,
        use_mock: bool,
        new_args: &Option<Vec<ScriptArgument>>,
        verbose: bool,
        print_layout: bool,
    ) -> VmResult<()> {
        logger::init_for_main(verbose);

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
        let (compiled_script, compiled_modules) = compile_script(targets)?;

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
            .global_ops_num(config.global_ops_num);
        let witness = runtime.execute_script(
            script.clone(),
            compiled_modules.clone(),
            config.ty_args.clone(),
            config.signer.clone(),
            config.args,
            &mut state,
            circuit_config.clone(),
        )?;
        let vm_circuit = VmCircuit { witness };
        info!("find the best k...");
        let k = runtime.find_best_k(&vm_circuit, vec![])?;
        info!("k = {}", k);

        if use_mock {
            info!("run with mock prover...");
            runtime.mock_prove_circuit(&vm_circuit, vec![], k)?;
        }

        if print_layout {
            info!("print circuit layout into layout.svg ...");
            runtime.print_circuit_layout(k, &vm_circuit);
        }

        info!("setup vm circuit...");
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
        let pk = runtime.setup_vm_circuit(&vm_circuit, &params)?;

        info!("prove vm circuit...");
        runtime.prove_vm_circuit(vm_circuit, &[], &params, pk.clone())?;
        #[allow(clippy::or_fun_call)]
        if let Some(new_args) = new_args
            .as_ref()
            .or(config.new_args.as_ref().map(|t| t.as_inner()))
        {
            info!("execute script with new arguments");
            let arguments = Some(ScriptArguments::new(new_args.clone()));
            let new_witness = runtime.execute_script(
                script,
                compiled_modules,
                if config.new_ty_args.is_empty() {
                    config.ty_args
                } else {
                    config.new_ty_args
                },
                config.signer,
                arguments,
                &mut state,
                circuit_config,
            )?;
            let new_vm_circuit = VmCircuit {
                witness: new_witness,
            };
            info!("prove the new execution with old proving key...");
            runtime.prove_vm_circuit(new_vm_circuit, &[], &params, pk)?;
        }

        Ok(())
    }
}

fn main() {
    let args = Arguments::from_args();

    let result = match args.cmd {
        Command::Run {
            ref script,
            ref modules,
            use_mock,
            ref new_args,
            verbose,
            print_layout,
        } => args.run(
            script.as_path(),
            modules,
            use_mock,
            new_args,
            verbose,
            print_layout,
        ),
        Command::CallGraph { module, output } => {
            std::fs::create_dir_all(output.as_path()).unwrap();
            let graphs = generate(std::fs::read(module.as_path()).unwrap());
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
