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
use vm_circuit::circuit_inputs::bytecode_table::BytecodeTable;

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
        let (compiled_script, compiled_modules) = compile_script(&targets)?;

        let script = compiled_script.expect("script is missing");
        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;
        let runtime = Runtime::<Fp>::new();
        let mut state = StateStore::new();
        for module in compiled_modules.clone().into_iter() {
            state.add_module(module);
        }

        if fast_mode {
            let k = runtime.find_best_k_for_fast_circuit(
                script_bytes.clone(),
                compiled_modules.clone(),
                config.args.clone(),
                &mut state,
            )?;
            info!("k = {}", k);

            if use_mock {
                runtime.mock_prove_script(
                    script_bytes.clone(),
                    compiled_modules.clone(),
                    config.args.clone(),
                    &mut state,
                    k,
                )?;
            }

            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_script(
                script_bytes.clone(),
                compiled_modules.clone(),
                &mut state,
                &params,
            )?;

            runtime.prove_script(
                script_bytes.clone(),
                compiled_modules.clone(),
                config.args.clone(),
                &mut state,
                &params,
                pk,
            )?;
        } else {
            let bytecodes = BytecodeTable::from((script, compiled_modules.clone()));
            let (exec_steps, rw_operations) =
                runtime.generate_trace(script_bytes, compiled_modules, config.args, &mut state)?;

            let vm_circuit = runtime.create_vm_circuit(
                exec_steps.clone(),
                rw_operations.clone(),
                bytecodes.clone(),
            );
            let k = runtime.find_best_k(&vm_circuit, vec![])?;
            info!("k = {}", k);

            if use_mock {
                runtime.mock_prove_execution_trace(
                    exec_steps.clone(),
                    rw_operations.clone(),
                    bytecodes.clone(),
                    k,
                )?;
            }

            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_execution_trace(
                exec_steps.clone(),
                rw_operations.clone(),
                bytecodes.clone(),
                &params,
            )?;

            runtime.prove_execution_trace(exec_steps, rw_operations, bytecodes, &params, pk)?;
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
