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
use structopt::StructOpt;
use vm_circuit::circuit_v2::VmCircuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{best_k, print_cs_info, prove_and_verify_kzg, setup_circuit, SubCircuit};

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

        #[structopt(short = "d", long = "debug", help = "debug with mock prover")]
        debug: bool,
    },
}

impl Arguments {
    pub fn run(&self, witness: &Path, debug: bool) -> Result<()> {
        logger::init_for_main(debug);

        debug!("witness {:?}", witness.display());

        // Always root ourselves to the package root, and then compile relative to that.
        let rooted_path = SourcePackageLayout::try_find_root(&witness.canonicalize()?)?;
        let manifest = {
            let manifest_string =
                std::fs::read_to_string(rooted_path.join(SourcePackageLayout::Manifest.path()))?;
            let toml_manifest =
                move_package::source_package::manifest_parser::parse_move_manifest_string(
                    manifest_string,
                )?;
            move_package::source_package::manifest_parser::parse_source_manifest(toml_manifest)?
        };

        let package = {
            let package_name = manifest.package.name.to_string();
            let build_path = rooted_path
                .join(CompiledPackageLayout::Root.path())
                .join(&package_name);
            let package = OnDiskCompiledPackage::from_path(build_path.as_path())?;
            package.into_compiled_package()?
        };

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

        // we can't use mock, because we compile the cli without test-circuit feature
        // if debug {
        //     debug!("Mock prove");
        //     mock_prove_circuit(&circuit, vec![], k)?;
        // }

        debug!("Generate parameters");
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let params = ParamsKZG::<Bn256>::setup(k, rng);
        let (vk, pk) = setup_circuit(&circuit, &params)?;
        if debug {
            print_cs_info(vk.cs());
        }
        debug!("Generate zk proof");
        prove_and_verify_kzg(circuit, &[], &params, pk.clone());

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Arguments::from_args();

    match args.cmd {
        Command::Run { ref witness, debug } => args.run(witness.as_path(), debug),
    }
}
