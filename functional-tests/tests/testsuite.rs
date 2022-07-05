// Copyright (c) zkMove Authors

use functional_tests::run_config::{Circuit, RunConfig};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::Params;
use logger::prelude::*;
use movelang::compiler::compile_script;
use movelang::state::StateStore;
use std::path::Path;
use vm::runtime::Runtime;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;

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
    let script = compiled_script.expect("script is missing");
    let runtime = Runtime::<Fp>::new();
    let mut state = StateStore::new();

    for module in compiled_modules.clone().into_iter() {
        state.add_module(module);
    }

    let (use_fast_circuit, use_vm_circuit) = match config.circuit {
        Some(Circuit::FastCircuit) => (true, false),
        Some(Circuit::VmCircuit) => (false, true),
        None => (true, true),
    };

    if use_fast_circuit {
        let move_circuit = runtime.create_move_circuit(
            script.clone(),
            compiled_modules.clone(),
            config.args.clone(),
            state.clone(),
        );
        let public_inputs = vec![Fp::zero()];
        debug!("Find the best suitable k for the circuit...");
        let k = runtime.find_best_k(&move_circuit, vec![public_inputs.clone()])?;
        info!("use move circuit, k = {}", k);

        debug!(
            "Generate zk proof for script {:?} with mock prover",
            script_file
        );
        runtime.mock_prove_circuit(&move_circuit, vec![public_inputs.clone()], k)?;

        debug!("Generate parameters for script {:?}", script_file);
        let params: Params<EqAffine> = Params::new(k);
        let pk = runtime.setup_move_circuit(&move_circuit, &params)?;

        debug!(
            "Generate zk proof for script {:?} with real prover",
            script_file
        );
        runtime.prove_move_circuit(move_circuit, &[public_inputs.as_slice()], &params, pk)?;
    }

    if use_vm_circuit {
        debug!("Generate execution trace for script {:?}", script_file);
        let circuit_config = CircuitConfig::default()
            .steps_num(config.steps_num)
            .stack_ops_num(config.stack_ops_num)
            .locals_ops_num(config.locals_ops_num);

        let witness = runtime.execute_script(
            script,
            compiled_modules,
            config.args,
            &state,
            circuit_config,
        )?;
        debug!("{:?}", witness);

        let vm_circuit = VmCircuit { witness };
        let k = runtime.find_best_k(&vm_circuit, vec![])?;
        info!("use vm circuit, k = {}", k);

        runtime.mock_prove_circuit(&vm_circuit, vec![], k)?;

        debug!("Generate parameters for execution trace");
        let params: Params<EqAffine> = Params::new(k);
        let pk = runtime.setup_vm_circuit(&vm_circuit, &params)?;

        debug!("Generate zk proof for execution trace");
        runtime.prove_vm_circuit(vm_circuit, &[], &params, pk)?;
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "tests/scripts", r".*\.move");
