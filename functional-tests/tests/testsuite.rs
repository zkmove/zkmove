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

    let mut targets = vec![script_file.to_string()];
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

    let (_use_fast_circuit, use_vm_circuit) = match config.circuit {
        Some(Circuit::FastCircuit) => (true, false),
        Some(Circuit::VmCircuit) => (false, true),
        None => (true, true),
    };

    if use_vm_circuit {
        debug!("Generate execution trace for script {:?}", script_file);
        let circuit_config = CircuitConfig::default()
            .steps_num(config.steps_num)
            .stack_ops_num(config.stack_ops_num)
            .locals_ops_num(config.locals_ops_num);

        let witness = runtime.execute_script(
            script,
            compiled_modules,
            config.ty_args,
            config.signer,
            config.args,
            &mut state,
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
