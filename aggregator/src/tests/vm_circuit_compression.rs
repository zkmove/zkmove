use super::SimpleVmCircuit;
use anyhow::Result;
use ark_std::test_rng;
use halo2_base::halo2_proofs;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::poly::kzg::commitment::ParamsKZG; //guangyuz
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs,
    pcs::kzg::{Bdfg21, Kzg},
};
use snark_verifier_sdk::{
    evm_verify, gen_evm_proof_shplonk, gen_evm_verifier, gen_pk, gen_snark_shplonk,
    AggregationCircuit, CircuitExt,
};
use std::path::Path;

#[test]
fn test_vm_circuit_compression() -> Result<()> {
    logger::init_for_test();
    std::env::set_var("VERIFY_CONFIG", "./configs/vm_circuit_aggregation.config");
    let param_path = Path::new("./params/kzg_bn254_25.srs");
    let mut param_file = std::fs::File::open(param_path)?;
    let params_outer = ParamsKZG::<Bn256>::read(&mut param_file)?;
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(10);
        params
    };

    let mut rng = test_rng();
    // Proof for vm circuit
    let vm_circuit = SimpleVmCircuit::<Fr>::new();
    let pk_inner = gen_pk(&params_inner, vm_circuit.circuit(), None);
    let vm_snark = gen_snark_shplonk(
        &params_inner,
        &pk_inner,
        vm_circuit.circuit().clone(),
        &mut rng,
        Some(Path::new("./data/vm_circuit.snark")),
    );
    println!("finished snark generation for vm circuit");

    // aggregation circuit
    let snarks = vec![vm_snark];
    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(&params_outer, &agg_circuit, None);
    println!("finished outer pk generation");
    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");

    // TODO: verify on move
    Ok(())
}
