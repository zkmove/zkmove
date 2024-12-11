use anyhow::Result;
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use aptos_move_witnesses::{Footprint, Operation};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::{Path, PathBuf};
use std::process::exit;
use structopt::StructOpt;
use vm_circuit::circuit_v2::VmCircuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{best_k, mock_prove_circuit, prove_and_verify_kzg, setup_circuit, SubCircuit};

#[derive(StructOpt)]
#[structopt(name = "zkmove", about = "CLI for zkMove")]
pub struct Arguments {
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    #[structopt(
        name = "run",
        about = "Run the full sequence of setup, proving, and verification."
    )]
    Run {
        #[structopt(
            short = "w",
            long = "witness",
            help = "path to .json file containing witness"
        )]
        witness: PathBuf,

        #[structopt(short = "p", long = "package", help = "move package name")]
        package: String,

        #[structopt(short = "d", long = "debug", help = "debug with mock prover")]
        debug: bool,
    },
    // #[structopt(name = "graph", about = "generate generic call graph")]
    // CallGraph { module: PathBuf, output: PathBuf },
}

impl Arguments {
    pub fn run(&self, witness: &Path, package: &String, debug: bool) -> Result<()> {
        logger::init_for_main(debug);

        debug!("witness {:?}", witness.display());

        // Always root ourselves to the package root, and then compile relative to that.
        let rooted_path = SourcePackageLayout::try_find_root(&witness.canonicalize()?)?;
        let build_path = rooted_path
            .join(CompiledPackageLayout::Root.path())
            .join(package.as_str());
        let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
        let package = package.into_compiled_package()?;
        let trace_contents = std::fs::read_to_string(witness)?;
        let traces: Vec<Footprint> = serde_json::from_str(&trace_contents)?;
        let entry = match &traces.first().unwrap().data {
            Operation::Start { entry_call } => entry_call,
            _ => unreachable!(),
        };
        let static_info = StaticInfo::generate(
            entry.module_id.as_ref().unwrap(),
            entry.function_index as u16,
            &package,
        );
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.pre_process(&traces, &static_info);
        let witness = WitnessV2::new(states, static_info, CircuitConfigV2::default());
        let circuit = VmCircuit::<Fr>::new_from_witness(&witness);

        let k = best_k(&circuit);
        debug!("k = {}", k);

        if debug {
            debug!("Mock prove");
            mock_prove_circuit(&circuit, vec![], k)?;
        }

        debug!("Generate parameters");
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let params = ParamsKZG::<Bn256>::setup(k, rng);
        let (_, pk) = setup_circuit(&circuit, &params)?;

        debug!("Generate zk proof");
        prove_and_verify_kzg(circuit, &[], &params, pk.clone());

        Ok(())
    }
}

fn main() {
    let args = Arguments::from_args();

    let result = match args.cmd {
        Command::Run {
            ref witness,
            ref package,
            debug,
        } => args.run(witness.as_path(), package, debug),
        // Command::CallGraph { module, output } => {
        //     std::fs::create_dir_all(output.as_path()).unwrap();
        //     let module =
        //         CompiledModule::deserialize(std::fs::read(module.as_path()).unwrap().as_ref())
        //             .unwrap();
        //     let store = {
        //         let mut s = RemoteStore::default();
        //         s.add_module(&module);
        //         s
        //     };
        //     let graphs = generate(&module.self_id(), &store);
        //     for (fname, graph) in graphs {
        //         std::fs::write(output.join(fname).with_extension("dot"), graph.to_dot()).unwrap();
        //     }
        //     Ok(())
        // }
    };

    if let Err(error) = result {
        error!("{}", error);
        exit(1);
    }
}
