#[cfg(feature = "test-circuits")]
mod tests {
    use halo2::proofs::best_k;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use move_core_types::{
        account_address::AccountAddress, identifier::Identifier, language_storage::ModuleId,
    };
    use std::{path::Path, process::Command, rc::Rc};
    use vm_circuit::{public_inputs::PublicInputs, CircuitConfigArgs, CircuitGuard, VmCircuit};
    use zkmove_cli::api::EntryArgument;

    #[test]
    fn second_arg_only_public_input() -> Result<(), Box<dyn std::error::Error>> {
        let package_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let build_status = Command::new("move")
            .args(["build", "--skip-fetch-latest-git-deps"])
            .current_dir(package_dir)
            .status()?;
        assert!(build_status.success(), "move build failed");

        let package = zkmove_cli::load_package(package_dir)?;
        let module_id = ModuleId::new(
            AccountAddress::from_hex_literal("0x2")?,
            Identifier::new("second_arg")?,
        );
        let traces = zkmove_cli::api::witness::generate_witness(
            &package,
            &module_id,
            "second_arg_only",
            &[EntryArgument::U8(1), EntryArgument::U64(25)],
        )?;

        let args = traces.args().expect("Args not found");
        let pubs_indices = vec![1usize];
        let public_inputs = PublicInputs::<Fr>::new(&args, &pubs_indices);
        let circuit_config_args = CircuitConfigArgs::new(None, 100);
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &pubs_indices,
            circuit_config_args,
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());
        let k = best_k(&circuit);

        if let Err(err) = MockProver::run(k, &*circuit, public_inputs.as_vec()) {
            panic!("mock prover assignment failed for pubs_indices=[1]: {err:?}");
        }
        Ok(())
    }
}
