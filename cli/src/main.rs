use error::VmResult;
use functional_tests::run_config::RunConfig;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::Params;
use logger::prelude::*;
use movelang::compiler::compile_script;
use movelang::state::StateStore;
use std::path::PathBuf;
use std::process::exit;
use structopt::StructOpt;
use vm::runtime::Runtime;
use vm_circuit::circuit::VmCircuit;

#[derive(StructOpt)]
#[structopt(name = "zkmove", about = "CLI for zkMove Virtual Machine")]
pub struct Arguments {
    #[structopt(short = "v", long = "verbose", global = false)]
    verbose: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    // Compile and run a Move script to generate a zero-knowledge proof,
    // and then verify the proof.
    #[structopt(name = "run")]
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
        modules: PathBuf,

        #[structopt(short = "f", long = "fast-mode", help = "use fast circuit")]
        fast_mode: bool,

        #[structopt(short = "d", long = "debug", help = "debug with mock prover")]
        use_mock: bool,
    },
}

impl Arguments {
    pub fn run(
        &self,
        script: &PathBuf,
        module_dir: &PathBuf,
        fast_mode: bool,
        use_mock: bool,
    ) -> VmResult<()> {
        let script_file = script.to_str().expect("path is None.");

        // compile script and depended modules
        let mut targets = vec![];
        targets.push(script_file.to_string());
        let config = RunConfig::new(script.as_path())?;
        for module in config.modules.into_iter() {
            let path = module_dir
                .as_path()
                .join(module)
                .to_str()
                .unwrap()
                .to_string();
            targets.push(path);
        }
        let (compiled_script, compiled_modules) = compile_script(targets)?;

        let script = compiled_script.expect("script is missing");
        let runtime = Runtime::<Fp>::new();
        let mut state = StateStore::new();
        for module in compiled_modules.clone().into_iter() {
            state.add_module(module);
        }

        if fast_mode {
            let move_circuit =
                runtime.create_move_circuit(script, compiled_modules, config.args, state);
            let public_inputs = vec![Fp::zero()];
            let k = runtime.find_best_k(&move_circuit, vec![public_inputs.clone()])?;
            info!("k = {}", k);

            if use_mock {
                runtime.mock_prove_circuit(&move_circuit, vec![public_inputs.clone()], k)?;
            }

            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_move_circuit(&move_circuit, &params)?;

            runtime.prove_move_circuit(move_circuit, &[public_inputs.as_slice()], &params, pk)?;
        } else {
            let witness = runtime.execute_script(
                script,
                compiled_modules,
                config.args,
                &state,
                None,
                None,
            )?;
            let vm_circuit = VmCircuit { witness };
            let k = runtime.find_best_k(&vm_circuit, vec![])?;
            info!("k = {}", k);

            if use_mock {
                runtime.mock_prove_circuit(&vm_circuit, vec![], k)?;
            }

            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_vm_circuit(&vm_circuit, &params)?;

            runtime.prove_vm_circuit(vm_circuit, &[], &params, pk)?;
        }

        Ok(())
    }
}

fn main() {
    let args = Arguments::from_args();

    logger::init_for_main(args.verbose);

    let result = match args.cmd {
        Command::Run {
            ref script,
            ref modules,
            fast_mode,
            use_mock,
        } => args.run(script, modules, fast_mode, use_mock),
    };

    if let Err(error) = result {
        error!("{}", error);
        exit(1);
    }
}
