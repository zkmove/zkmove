use anyhow::Result;
use clap::Parser;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use logger::prelude::*;
use move_package::compilation::compiled_package::OnDiskCompiledPackage;
use move_package::compilation::package_layout::CompiledPackageLayout;
use move_package::source_package::layout::SourcePackageLayout;
use std::path::PathBuf;
#[cfg(feature = "test-circuits")]
use vm_circuit::mock_prove_circuit;
use vm_circuit::{
    best_k, print_cs_info, prove_circuit, setup_circuit, verify_circuit, CircuitConfigV2,
    Footprints, InstanceFields, SubCircuit, VmCircuit, NUM_INSTANCE_COLUMNS,
};

#[derive(Parser)]
#[clap(name = "zkmove", about = "CLI for zkMove")]
pub struct Arguments {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(name = "prove", about = "Run the full sequence of setup and proving")]
    Prove {
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
            long = "pubs_indices",
            help = "Indices of arguments to be treated as public inputs (e.g., --pubs_indices 0 1)",
            value_parser = clap::value_parser!(usize),
            num_args = 0..,
        )]
        pubs_indices: Vec<usize>,
    },
}

impl Arguments {
    pub fn run(&self) -> Result<()> {
        let (witness, debug, pubs_indices) = match &self.cmd {
            Command::Prove {
                witness,
                debug,
                pubs_indices,
            } => (witness, *debug, pubs_indices),
        };

        logger::init_for_main(debug);
        debug!("witness {:?}", witness.display());

        let traces = Footprints::load(witness)?;
        let args = traces.args().expect("Args not found");

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
        let circuit =
            VmCircuit::<Fr>::new(&package, &traces, pubs_indices, CircuitConfigV2::default());
        circuit.register();

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
        let instances = InstanceFields::<_, NUM_INSTANCE_COLUMNS>::new(&args, pubs_indices);

        #[cfg(feature = "test-circuits")]
        if debug {
            debug!("Mock prove");
            mock_prove_circuit(&circuit, instances.0, k)?;
        }

        #[cfg(not(feature = "test-circuits"))]
        {
            let proof = prove_circuit(circuit, &instances.as_ref(), &params, &pk)
                .expect("proof generation should not fail");
            verify_circuit(&instances.as_ref(), &params, &vk, &proof)
                .expect("verify proof should be ok");
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Arguments::parse();
    match &args.cmd {
        Command::Prove {
            witness: _,
            debug: _,
            pubs_indices: _,
        } => args.run(),
    }
}
