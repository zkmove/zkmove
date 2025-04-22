use anyhow::{anyhow, Result};
use aptos_move_witnesses::static_info::StaticInfo;
use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use aptos_move_witnesses::{Footprint, Operation};
use clap::Parser;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::collections::HashSet;
use std::path::PathBuf;
use vm_circuit::chips::execution_chip_v2::instance::public_inputs_to_fields;
use vm_circuit::circuit_v2::VmCircuit;
use vm_circuit::witness::{CircuitConfigV2, WitnessV2};
use vm_circuit::{best_k, print_cs_info, prove_and_verify_kzg, setup_circuit, SubCircuit};

#[derive(Parser)]
#[clap(name = "zkmove", about = "CLI for zkMove")]
pub struct Arguments {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(
        name = "run",
        about = "Run the full sequence of setup, proving, and verification."
    )]
    Run {
        #[clap(
            short = 'w',
            long = "witness",
            help = "path to .json file containing witness"
        )]
        witness: PathBuf,

        #[clap(short = 'd', long = "debug", help = "debug with mock prover")]
        debug: bool,

        #[clap(
            short = 'p',
            long = "public-inputs",
            help = "Indices of arguments to be treated as public inputs (e.g., --public-inputs 0 1)",
            value_parser = clap::value_parser!(usize),
            num_args = 0..,
        )]
        public_inputs: Vec<usize>,
    },
}

impl Arguments {
    pub fn run(&self) -> Result<()> {
        let (witness, debug, public_inputs) = match &self.cmd {
            Command::Run {
                witness,
                debug,
                public_inputs,
            } => (witness, *debug, public_inputs),
        };

        logger::init_for_main(debug);
        debug!("witness {:?}", witness.display());

        let trace_contents = std::fs::read_to_string(witness)?;
        let traces: Vec<Footprint> = serde_json::from_str(&trace_contents)?;

        let first_trace = traces
            .first()
            .ok_or_else(|| anyhow!("In witness '{}': No traces found", witness.display()))?;
        let (input_count, entry) = match &first_trace.data {
            Operation::Start { entry_call } => (entry_call.args.len(), entry_call),
            _ => {
                return Err(anyhow!(
                    "In witness '{}': First trace is not a Start operation",
                    witness.display()
                ))
            }
        };

        // check public inputs
        for &index in public_inputs {
            if index >= input_count {
                return Err(anyhow!(
                    "Public input index {} out of bounds for input count {}",
                    index,
                    input_count
                ));
            }
        }
        let unique_indices: HashSet<_> = public_inputs.iter().collect();
        if unique_indices.len() != public_inputs.len() {
            return Err(anyhow!("Duplicate indices in public-inputs"));
        }

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

        let module_id = entry
            .module_id
            .as_ref()
            .ok_or_else(|| anyhow!("Module ID is missing for entry call"))?;
        let static_info = StaticInfo::generate(
            module_id,
            entry.function_index as u16,
            &package,
            public_inputs.as_slice(),
        );
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.pre_process(&traces, &static_info);
        let witness = WitnessV2::new(states, static_info, CircuitConfigV2::default());
        let circuit = VmCircuit::<Fr>::new_from_witness(&witness);

        let k = best_k(&circuit);
        debug!("k = {}", k);

        debug!("Generate parameters");
        let rng = rand::rngs::mock::StepRng::new(0, 1);
        let params = ParamsKZG::<Bn256>::setup(k, rng);
        let (vk, pk) = setup_circuit(&circuit, &params)?;
        if debug {
            print_cs_info(vk.cs());
        }
        debug!("Generate zk proof");
        let instances: Vec<Vec<Fr>> = public_inputs_to_fields(&entry.args, &public_inputs);
        // Convert to &[&[F]]
        let slices: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();
        let instances_ref: &[&[Fr]] = &slices;

        prove_and_verify_kzg(circuit, instances_ref, &params, pk.clone());

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    match &args.cmd {
        Command::Run {
            witness: _,
            debug: _,
            public_inputs: _,
        } => args.run(),
    }
}
