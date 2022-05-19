// Copyright (c) zkMove Authors

use functional_tests::run_config::{Circuit, RunConfig};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::Params;
use logger::prelude::*;
use movelang::compiler::compile_script;
use movelang::state::StateStore;
use std::path::Path;
use vm::runtime::Runtime;
use vm_circuit::circuit_inputs::bytecode_table::BytecodeTable;

pub const TEST_MODULE_PATH: &str = "tests/modules";

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    let script_file = path.to_str().expect("path is None.");
    debug!("Run test {:?}", script_file);

    let mut targets = vec![];
    targets.push(script_file.to_string());
    let config = RunConfig::new(path)?;
    for module in config.modules.into_iter() {
        let path = Path::new(TEST_MODULE_PATH)
            .join(module)
            .to_str()
            .unwrap()
            .to_string();
        targets.push(path);
    }
    debug!(
        "script arguments {:?}, compile targets {:?}",
        config.args, targets
    );

    let (compiled_script, compiled_modules) = compile_script(targets)?;

    if let Some(script) = compiled_script {
        let mut script_bytes = vec![];
        script.serialize(&mut script_bytes)?;

        let runtime = Runtime::<Fp>::new();
        let mut state = StateStore::new();

        // todo: refactor bytecode table, global state and module table
        let bytecodes = BytecodeTable::from((script, compiled_modules.clone()));
        for module in compiled_modules.clone().into_iter() {
            state.add_module(module);
        }

        let (use_fast_circuit, use_vm_circuit) = match config.circuit {
            Some(Circuit::FastCircuit) => (true, false),
            Some(Circuit::VmCircuit) => (false, true),
            None => (true, true),
        };

        if use_fast_circuit {
            debug!("Find the best suitable k for the circuit");
            let k = runtime.find_best_k_for_fast_circuit(
                script_bytes.clone(),
                compiled_modules.clone(),
                config.args.clone(),
                &mut state,
            )?;
            info!("k = {}", k);

            debug!(
                "Generate zk proof for script {:?} with mock prover",
                script_file
            );
            runtime.mock_prove_script(
                script_bytes.clone(),
                compiled_modules.clone(),
                config.args.clone(),
                &mut state,
                k,
            )?;

            debug!("Generate parameters for script {:?}", script_file);
            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_script(
                script_bytes.clone(),
                compiled_modules.clone(),
                &mut state,
                &params,
            )?;

            debug!(
                "Generate zk proof for script {:?} with real prover",
                script_file
            );
            runtime.prove_script(
                script_bytes.clone(),
                compiled_modules.clone(),
                config.args.clone(),
                &mut state,
                &params,
                pk,
            )?;
        }

        if use_vm_circuit {
            debug!("Generate execution trace for script {:?}", script_file);
            let (exec_steps, rw_operations) =
                runtime.generate_trace(script_bytes, compiled_modules, config.args, &mut state)?;

            let vm_circuit = runtime.create_vm_circuit(
                exec_steps.clone(),
                rw_operations.clone(),
                bytecodes.clone(),
            );
            let k = runtime.find_best_k(&vm_circuit, vec![])?;
            info!("k = {}", k);

            runtime.mock_prove_execution_trace(
                exec_steps.clone(),
                rw_operations.clone(),
                bytecodes.clone(),
                k,
            )?;

            debug!("Generate parameters for execution trace");
            let params: Params<EqAffine> = Params::new(k);
            let pk = runtime.setup_execution_trace(
                exec_steps.clone(),
                rw_operations.clone(),
                bytecodes.clone(),
                &params,
            )?;

            debug!("Generate zk proof for execution trace");
            runtime.prove_execution_trace(exec_steps, rw_operations, bytecodes, &params, pk)?;
        }
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "tests/scripts", r".*\.move");
