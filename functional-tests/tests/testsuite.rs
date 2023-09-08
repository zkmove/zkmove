// Copyright (c) zkMove Authors

use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use movelang::compiler::compile_source_files;
use std::path::Path;
use vm::runtime::Runtime;
use vm::state::StateStore;

use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;

use rand::{rngs::StdRng, SeedableRng};
use vm_circuit::{find_best_k, mock_prove_circuit, prove_vm_circuit_kzg, setup_vm_circuit};

pub const TEST_MODULE_PATH: &str = "tests/modules";

fn vm_test(path: &Path) -> datatest_stable::Result<()> {
    logger::init_for_test();
    let source_file = path.to_str().expect("path is None.");
    debug!("Run test {:?}", source_file);

    let mut targets = vec![source_file.to_string()];
    let config = RunConfig::new(path)?;
    for module in config.modules.into_iter() {
        let path = Path::new(TEST_MODULE_PATH)
            .join(module)
            .to_str()
            .unwrap()
            .to_string();
        targets.push(path);
    }
    debug!("arguments {:?}, compile targets {:?}", config.args, targets);

    let (compiled_script, compiled_modules) = compile_source_files(targets)?;
    let runtime = Runtime::<Fr>::new()
        .ext_web3("https://cloudflare-eth.com")
        .unwrap();
    let mut state = StateStore::new();

    for module in compiled_modules.clone().into_iter() {
        state.add_module(module);
    }

    debug!("Generate execution trace for {:?}", source_file);
    let circuit_config = CircuitConfig::default()
        .max_step_row(config.step_max_row)
        .stack_ops_num(config.stack_ops_num)
        .locals_ops_num(config.locals_ops_num)
        .global_ops_num(config.global_ops_num)
        .word_size(config.word_capacity);

    let witness = match compiled_script.clone() {
        Some(script) => {
            let trace = runtime.execute_script(
                script.clone(),
                config.ty_args.clone(),
                config.signer.clone(),
                config.args,
                &mut state,
            )?;
            runtime.process_execution_trace(
                config.ty_args.clone(),
                Some(script),
                compiled_modules.clone(),
                trace,
                circuit_config.clone(),
            )?
        }
        None => {
            if let Some(function_name) = config.entry_fun_name.clone() {
                let module_id = config
                    .module_id
                    .clone()
                    .expect("module_id should not be None.");
                let trace = runtime.execute_entry_function(
                    &module_id,
                    &function_name,
                    config.ty_args.clone(),
                    config.signer.clone(),
                    config.args,
                    &mut state,
                )?;
                runtime.process_execution_trace(
                    config.ty_args.clone(),
                    None,
                    compiled_modules.clone(),
                    trace,
                    circuit_config.clone(),
                )?
            } else {
                return Ok(());
            }
        }
    };

    debug!("{:?}", witness);

    let vm_circuit = VmCircuit { witness };
    let k = find_best_k(&vm_circuit, vec![])?;
    info!("use vm circuit, k = {}", k);

    mock_prove_circuit(&vm_circuit, vec![], k)?;

    debug!("Generate parameters for execution trace");
    let rng = StdRng::from_entropy();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let (_, pk) = setup_vm_circuit(&vm_circuit, &params)?;

    debug!("Generate zk proof for execution trace");
    prove_vm_circuit_kzg(vm_circuit, &[], &params, pk.clone())?;
    if let Some(new_args) = config.new_args.as_ref() {
        info!("execute with new arguments");
        let new_ty_args = if config.new_ty_args.is_empty() {
            config.ty_args
        } else {
            config.new_ty_args
        };
        let new_witness = match compiled_script {
            Some(script) => {
                let trace = runtime.execute_script(
                    script.clone(),
                    new_ty_args.clone(),
                    config.signer,
                    Some(new_args.clone()),
                    &mut state,
                )?;
                runtime.process_execution_trace(
                    new_ty_args,
                    Some(script),
                    compiled_modules,
                    trace,
                    circuit_config,
                )?
            }
            None => {
                if let Some(function_name) = config.entry_fun_name.clone() {
                    let module_id = config
                        .module_id
                        .clone()
                        .expect("module_id should not be None.");
                    let trace = runtime.execute_entry_function(
                        &module_id,
                        &function_name,
                        new_ty_args.clone(),
                        config.signer.clone(),
                        Some(new_args.clone()),
                        &mut state,
                    )?;
                    runtime.process_execution_trace(
                        new_ty_args,
                        None,
                        compiled_modules,
                        trace,
                        circuit_config,
                    )?
                } else {
                    return Ok(());
                }
            }
        };
        let new_vm_circuit = VmCircuit {
            witness: new_witness,
        };
        info!("prove the new execution with old proving key...");
        prove_vm_circuit_kzg(new_vm_circuit, &[], &params, pk)?;
    }

    Ok(())
}

datatest_stable::harness!(vm_test, "tests", r".*\.move");
