// Copyright (c) zkMove Authors

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode};
use functional_tests::run_config::RunConfig;
use halo2_proofs::halo2curves::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::ipa::commitment::ParamsIPA;
use logger::{debug, info};
use movelang::compiler::compile_script;
use movelang::state::StateStore;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vm::runtime::Runtime;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::CircuitConfig;

pub const TEST_MODULE_PATH: &str = "tests/modules";
#[allow(clippy::type_complexity)]
fn setup(
    path: &Path,
) -> datatest_stable::Result<(
    Runtime<Fp>,
    VmCircuit<Fp>,
    ParamsIPA<EqAffine>,
    ProvingKey<EqAffine>,
)> {
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

    debug!("Generate execution trace for script {:?}", script_file);
    let circuit_config = CircuitConfig::default()
        .max_step_row(config.step_max_row)
        .stack_ops_num(config.stack_ops_num)
        .locals_ops_num(config.locals_ops_num)
        .global_ops_num(config.global_ops_num);

    let witness = runtime.execute_script(
        script,
        compiled_modules,
        config.ty_args.clone(),
        config.signer.clone(),
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
    let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
    let pk = runtime.setup_vm_circuit(&vm_circuit, &params)?;
    Ok((runtime, vm_circuit, params, pk))
}

// Circuit benchmarks
fn circuit_benchmark(c: &mut Criterion) {
    let root = Path::new("benches/scripts");
    let re = regex::Regex::new(r".*\.move").unwrap();
    let cases: Vec<_> = iterate_directory(root)
        .filter_map(|path| {
            if re.is_match(path.to_string_lossy().as_ref()) {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    let mut group = c.benchmark_group("vm-circuit");
    group
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(60));
    for case_path in cases {
        let inputs = setup(case_path.as_path()).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(&case_path.display()),
            &inputs,
            |b, (runtime, vm_circuit, params, pk)| {
                b.iter_batched(
                    || {},
                    |_| {
                        runtime
                            .prove_vm_circuit(vm_circuit.clone(), &[], params, pk.clone())
                            .unwrap();
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
}

criterion_group!(
    name = circuit_benches;
    config = Criterion::default().sample_size(3).measurement_time(Duration::from_secs(60*5)).without_plots();
    targets = circuit_benchmark
);

criterion_main!(circuit_benches);

fn iterate_directory(path: &Path) -> impl Iterator<Item = PathBuf> {
    walkdir::WalkDir::new(path)
        .into_iter()
        .map(::std::result::Result::unwrap)
        .filter(|entry| {
            entry.file_type().is_file()
                && entry
                    .file_name()
                    .to_str()
                    .map_or(false, |s| !s.starts_with('.')) // Skip hidden files
        })
        .map(|entry| entry.path().to_path_buf())
}
